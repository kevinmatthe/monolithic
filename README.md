# Monolithic Game Download Cache Docker Container

![Docker Pulls](https://img.shields.io/docker/pulls/lancachenet/monolithic?label=Monolithic) ![Docker Pulls](https://img.shields.io/docker/pulls/lancachenet/lancache-dns?label=Lancache-dns) ![Docker Pulls](https://img.shields.io/docker/pulls/lancachenet/sniproxy?label=Sniproxy) ![Docker Pulls](https://img.shields.io/docker/pulls/lancachenet/generic?label=Generic)

## Documentation

The documentation for the LanCache.net project can be found on [our website](http://www.lancache.net)

The specific documentation for this monolithic container is [here](http://lancache.net/docs/containers/monolithic/)

If you have any problems after reading the documentation please see [the support page](http://lancache.net/support/) before opening a new issue on github.

## Experimental origin connection reuse

`ORIGIN_KEEPALIVE_ENABLED=true` opts in to per-origin HTTP/1.1 keepalive pools.
The default is `false`; normal nginx routing is retained when disabled.
The optional implementation discovers real hostnames from successful cache
requests and a separate hostname-only redirect log. It also pools the internal
cache-to-proxy hop, HTTP/HTTPS redirect targets, and existing updater exceptions.
Original Host, signed path/query, TLS SNI, slice size and cache keys are preserved.

For observed HTTP redirect issuers, an internal loopback-only listener on 3129
finishes the origin response before the outer proxy intercepts its redirect.
This addresses an extra source of connection churn beyond adding HTTP/1.1 to
the primary location. Do not publish this port. Existing interception semantics
remain limited to 301/302/307; relative redirects, nonstandard ports and arbitrary
redirect chains are not expanded by this feature. TCP TLS passthrough is unchanged.

The helper requires Python 3 and `dig` (declared in the Dockerfile). It queries
`UPSTREAM_DNS` directly rather than system DNS, which may resolve cache domains
back to LANCache. Only public IPv4 origin addresses enter generated pools. Resolver
endpoints accept an optional port, including bracketed IPv6 resolver addresses.

Optional tuning (positive seconds/counts):

| Variable | Default | Purpose |
| --- | --- | --- |
| `ORIGIN_KEEPALIVE_MAX_HOSTS` | `64` | Active host limit, capped at 1024; resolver entries are limited to twice this count |
| `ORIGIN_KEEPALIVE_INTERVAL` | `15` | Discovery interval |
| `ORIGIN_KEEPALIVE_DNS_TTL` | `300` | Positive DNS cache lifetime |
| `ORIGIN_KEEPALIVE_DNS_FAILURE_TTL` | `30` | Failed DNS retry interval |
| `ORIGIN_KEEPALIVE_SEED_HOSTS` | empty | Optional comma/space-separated origin names to warm before traffic arrives |

Generated addresses and redirect-issuer state live in
`/data/info/cdn-origin/upstreams.conf`; persist `/data/info` to reuse this state
after recreation. Updates use an atomic write, `nginx -t`, graceful reload and
file rollback on failure. DNS failures retain prior addresses. The redirect
log stores only hostnames, is read through a bounded tail, and is truncated above
1 MiB. The main access log is never truncated by this helper. Discovery currently
parses the default text `cachelog`; custom/JSON access logs require seed hosts or
redirect observations and need follow-up parser support.

Run `python3 -m unittest discover -s tests -v` for discovery, resolver, bounded
state, and file-validation tests. Mocked reload tests do not demonstrate that a
running nginx worker adopted a configuration; container checks are also needed.

Local short A/B samples using the same CDN IP/request and 32-way concurrency
measured 96.94 MB/s with fresh HTTP/1.0 connections and 154.96 MB/s with pools,
with zero request errors. These are workload-specific samples, not sustained
client throughput guarantees. Three updater exceptions were checked as nginx
configuration only, without their native clients. See existing upstream issue
[#202](https://github.com/lancachenet/monolithic/issues/202) and PR
[#217](https://github.com/lancachenet/monolithic/pull/217) for related work; this
experimental implementation is offered for discussion of the additional scope.

## Thanks

- Based on original configs from [ansible-lanparty](https://github.com/ti-mo/ansible-lanparty).
- Everyone on [/r/lanparty](https://reddit.com/r/lanparty) who has provided feedback and helped people with this.
- UK LAN Techs for all the support.

## License

The MIT License (MIT)

Copyright (c) 2019 Jessica Smith, Robin Lewis, Brian Wojtczak, Jason Rivers, James Kinsman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
