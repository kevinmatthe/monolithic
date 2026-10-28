#!/usr/bin/env python3
"""Discover content origins and maintain keepalive pools with last-good DNS/config state."""
import argparse
from collections import OrderedDict
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

# No region-specific seeds are required; traffic discovers origin hostnames.
HOSTS = ()
MAX_HOSTS = max(1, min(1024, int(os.environ.get('ORIGIN_KEEPALIVE_MAX_HOSTS', '64'))))
REFRESH_INTERVAL = max(1, int(os.environ.get('ORIGIN_KEEPALIVE_INTERVAL', '15')))
DNS_TTL = max(1, int(os.environ.get('ORIGIN_KEEPALIVE_DNS_TTL', '300')))
DNS_FAILURE_TTL = max(1, int(os.environ.get('ORIGIN_KEEPALIVE_DNS_FAILURE_TTL', '30')))
LOCAL_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in ('0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4'))


def normalize_host(value):
    value = value.lower().strip().rstrip('.')
    if ':' in value:
        value, port = value.rsplit(':', 1)
        if not port.isdigit():
            return None
    if value == 'lancache.steamcontent.com' or len(value) > 253:
        return None
    labels = value.split('.')
    if len(labels) < 2 or all(label.isdigit() for label in labels):
        return None
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        return None
    return value


def pool_name(host):
    return dict(HOSTS).get(host, 'lancache_origin_' + hashlib.sha256(host.encode()).hexdigest()[:16])


def resolve_dns(host):
    # System DNS may point back at lancache-dns. Query the same upstream resolvers
    # configured for nginx, otherwise generated pools could route into this cache.
    errors = []
    resolvers = os.environ.get('UPSTREAM_DNS', '8.8.8.8 8.8.4.4').replace(';', ' ').split()
    for endpoint in resolvers:
        try:
            if endpoint.startswith('['):
                address, separator, port = endpoint[1:].partition(']')
                if not separator or (port and not port.startswith(':')):
                    raise ValueError('Invalid resolver endpoint')
                port = port[1:] if port else '53'
            elif endpoint.count(':') == 1:
                address, port = endpoint.rsplit(':', 1)
            else:
                address, port = endpoint, '53'
            ipaddress.ip_address(address)
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError('Invalid resolver port')
            result = subprocess.run(['dig', '+short', '+time=2', '+tries=1', '@' + address,
                                     '-p', port, host, 'A'], capture_output=True, text=True, timeout=5, check=True)
            addresses = []
            for line in result.stdout.splitlines():
                try:
                    addresses.append(str(ipaddress.IPv4Address(line.strip())))
                except ValueError:
                    pass  # dig may emit intermediate CNAMEs before the final addresses.
            if addresses:
                return addresses
            raise OSError('Resolver returned no IPv4 addresses')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(error)
    raise OSError('No configured upstream resolver returned an origin address') from (errors[-1] if errors else None)


def render(records, redirect_issuers=()):
    lines = ['# Generated origin pools. No account credentials are stored here.']
    for host in sorted(records):
        if normalize_host(host) != host:
            raise ValueError('Invalid origin hostname')
        name = pool_name(host)
        parsed = {ipaddress.IPv4Address(address) for address in records[host]}
        if any(any(address in network for network in LOCAL_NETWORKS) for address in parsed):
            raise ValueError('Origin resolves to a local address')
        addresses = sorted(str(address) for address in parsed)
        if not addresses:
            raise OSError('No IPv4 addresses for ' + host)
        for suffix, port in [('', 80), ('_tls', 443)]:
            lines.append('upstream ' + name + suffix + ' {')
            lines.extend('    server ' + address + ':' + str(port) + ' max_fails=2 fail_timeout=10s;' for address in addresses)
            lines.extend(['    keepalive 64;', '    keepalive_requests 1000;', '    keepalive_timeout 30s;', '}'])
    lines.extend(['map $host $lancache_origin_backend {', '    default $host;'])
    lines.extend('    ' + host + ' ' + pool_name(host) + ';' for host in sorted(records))
    lines.append('}')
    lines.extend(['map $host $lancache_primary_backend {', '    default $lancache_origin_backend;'])
    lines.extend('    ' + host + ' lancache_redirect_gateway;' for host in sorted(set(redirect_issuers) & set(records)))
    lines.append('}')
    for variable, suffix in [('http', ''), ('https', '_tls')]:
        lines.extend(['map $lancache_redirect_host $lancache_redirect_' + variable + '_backend {', '    default $lancache_redirect_host;'])
        lines.extend('    ' + host + ' ' + pool_name(host) + suffix + ';' for host in sorted(records))
        lines.append('}')
    return '\n'.join(lines) + '\n'


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, filename = tempfile.mkstemp(prefix='.origin-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(filename, 0o644)
        os.replace(filename, path)
    finally:
        if os.path.exists(filename):
            os.unlink(filename)


def discover_hosts(path):
    path = Path(path)
    if not path.exists():
        return []
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 524288))
        lines = stream.read().decode('utf-8', errors='replace').splitlines()
    result = []
    seen = set()
    for line in reversed(lines):
        if not re.search(r'HTTP/[^"]+"\s+(?:200|206)\s+', line):
            continue
        quoted = re.findall(r'"([^"\n]*)"', line)
        if len(quoted) < 6:
            continue
        host = normalize_host(quoted[-2])
        if host and host not in seen:
            seen.add(host)
            result.append(host)
        if len(result) >= MAX_HOSTS:
            break
    return result


def previous_records(content):
    groups = {name: re.findall(r'\bserver\s+([0-9.]+):(?:80|443)\b', body)
              for name, body in re.findall(r'upstream\s+(\w+)\s*\{([^}]+)\}', content)}
    return {host: groups[name] for host, name in re.findall(r'^\s+([a-z0-9.-]+)\s+(lancache_\w+);', content, re.MULTILINE)
            if normalize_host(host) == host and name in groups}


def redirect_log_lines(path, truncate=False):
    path = Path(path)
    if not path.exists():
        return []
    with path.open('rb') as stream:
        size = path.stat().st_size
        stream.seek(max(0, size - 524288))
        lines = stream.read().decode('utf-8', errors='replace').splitlines()
    # This is our dedicated hostname-only discovery log, never the primary access log.
    if truncate and size > 1048576 and path.name == 'origin-redirect-hosts.log':
        with path.open('r+b') as stream:
            stream.truncate(0)
    return lines


def discover_redirect_hosts(path):
    return list(dict.fromkeys(host for line in reversed(redirect_log_lines(path, truncate=True))
                              for part in line.split() if (host := normalize_host(part))))[:MAX_HOSTS]


def discover_redirect_issuers(path):
    return list(dict.fromkeys(host for line in reversed(redirect_log_lines(path))
                              if len(parts := line.split()) == 2 and (host := normalize_host(parts[0]))))[:MAX_HOSTS]


def previous_redirect_issuers(content):
    return re.findall(r'^\s+([a-z0-9.-]+)\s+lancache_redirect_gateway;', content, re.MULTILINE)


def selected_hosts(path, access_log, redirect_log=None):
    previous = previous_records(Path(path).read_text()) if Path(path).exists() else {}
    redirected = discover_redirect_hosts(redirect_log) if redirect_log is not None else []
    return list(dict.fromkeys(redirected + discover_hosts(access_log) + list(previous) + [host for host, _ in HOSTS]))[:MAX_HOSTS]


class CachingResolver:
    def __init__(self, resolve=resolve_dns, clock=time.monotonic):
        self.resolve = resolve
        self.clock = clock
        self.entries = OrderedDict()

    def __call__(self, host):
        now = self.clock()
        cached = self.entries.get(host)
        if cached:
            self.entries.move_to_end(host)
        elif len(self.entries) >= MAX_HOSTS * 2:
            self.entries.popitem(last=False)
        if cached and now < cached[0]:
            if isinstance(cached[1], Exception):
                raise cached[1]
            return cached[1]
        try:
            value = self.resolve(host)
            self.entries[host] = (now + DNS_TTL, value)
            return value
        except Exception as error:
            if cached and not isinstance(cached[1], Exception):
                self.entries[host] = (now + DNS_FAILURE_TTL, cached[1])
                return cached[1]
            self.entries[host] = (now + DNS_FAILURE_TTL, error)
            raise


def refresh(path, resolve=resolve_dns, run=subprocess.run, bootstrap=False, hosts=None, redirect_issuers=()):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with (path.parent / '.refresh.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = path.read_text() if path.exists() else None
        previous_hosts = previous_records(previous or '')
        records = {}
        errors = []
        for host in hosts if hosts is not None else [host for host, _ in HOSTS]:
            try:
                records[host] = resolve(host)
            except Exception as error:
                errors.append(error)
                if host in previous_hosts:
                    records[host] = previous_hosts[host]
        if not records and errors:
            raise errors[0]
        issuers = previous_redirect_issuers(previous or '') + list(redirect_issuers)
        content = render(records, issuers)
        if previous == content:
            return False
        atomic_write(path, content)
        if bootstrap:
            return True
        try:
            for command in (['nginx', '-t'], ['nginx', '-s', 'reload']):
                result = run(command, capture_output=True, text=True, timeout=10)
                if result.returncode:
                    raise RuntimeError('Origin configuration validation/reload failed')
        except Exception:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, previous)
            raise
        return True


def bootstrap(path, resolve=resolve_dns, run=subprocess.run, hosts=None, redirect_issuers=()):
    try:
        saved = previous_records(Path(path).read_text()) if Path(path).exists() else {}
        if saved:
            # Start from the saved addresses immediately; the watcher refreshes DNS
            # after nginx is serving, rather than delaying availability per hostname.
            refresh(path, saved.__getitem__, run, bootstrap=True, hosts=list(saved), redirect_issuers=redirect_issuers)
            return
        refresh(path, resolve, run, bootstrap=True, hosts=hosts, redirect_issuers=redirect_issuers)
    except Exception as error:
        if not Path(path).exists():
            atomic_write(path, render({}))
        print('Origin DNS unavailable; retaining existing/default routing (' + type(error).__name__ + ')', flush=True)


def main():
    global HOSTS
    seeds = os.environ.get('ORIGIN_KEEPALIVE_SEED_HOSTS', '').replace(',', ' ').split()
    normalized = [normalize_host(host) for host in seeds]
    if any(host is None for host in normalized):
        raise ValueError('Invalid ORIGIN_KEEPALIVE_SEED_HOSTS hostname')
    HOSTS = tuple((host, 'lancache_origin_' + hashlib.sha256(host.encode()).hexdigest()[:16])
                  for host in dict.fromkeys(normalized))
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--bootstrap', action='store_true')
    modes.add_argument('--watch', action='store_true')
    modes.add_argument('--once', action='store_true')
    parser.add_argument('--state-file', default='/data/info/cdn-origin/upstreams.conf')
    parser.add_argument('--access-log', default='/data/logs/access.log')
    parser.add_argument('--redirect-log', default='/data/logs/origin-redirect-hosts.log')
    options = parser.parse_args()
    resolver = CachingResolver()
    if options.bootstrap:
        issuers = discover_redirect_issuers(options.redirect_log)
        bootstrap(options.state_file, resolver, hosts=selected_hosts(options.state_file, options.access_log, options.redirect_log), redirect_issuers=issuers)
    elif options.once:
        issuers = discover_redirect_issuers(options.redirect_log)
        refresh(options.state_file, resolver, hosts=selected_hosts(options.state_file, options.access_log, options.redirect_log), redirect_issuers=issuers)
    else:
        while True:
            time.sleep(REFRESH_INTERVAL)
            try:
                issuers = discover_redirect_issuers(options.redirect_log)
                if refresh(options.state_file, resolver, hosts=selected_hosts(options.state_file, options.access_log, options.redirect_log), redirect_issuers=issuers):
                    print('Origin hosts/DNS changed; pools refreshed with graceful nginx reload', flush=True)
            except Exception as error:
                print('Origin refresh deferred; retaining last good configuration (' + type(error).__name__ + ')', flush=True)


if __name__ == '__main__':
    main()
