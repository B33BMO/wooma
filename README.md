# wooma

A flowy terminal toolkit for network and IT tooling, written in Rust.

```
██╗    ██╗ ██████╗  ██████╗ ███╗   ███╗ █████╗
██║    ██║██╔═══██╗██╔═══██╗████╗ ████║██╔══██╗
██║ █╗ ██║██║   ██║██║   ██║██╔████╔██║███████║
██║███╗██║██║   ██║██║   ██║██║╚██╔╝██║██╔══██║
╚███╔███╔╝╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║
 ╚══╝╚══╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝
```

## Tools

| tab | what it does |
|-----|--------------|
| **1 ping** | Ping many hosts at once. Live up/down state with flap count, loss %, min/avg/max, stddev, jitter, a scrolling latency chart and a status-page style timeline. |
| **2 trace** | Continuous mtr-style traceroute. Per-hop loss, last/avg/best/worst/stdev, reverse DNS, ASN + owner + country (via Team Cymru), ECMP detection, and an animated path map. |
| **3 dns** | Queries A, AAAA, CNAME, MX, NS, TXT, SOA and CAA in parallel with TTLs and per-type timing, races system/Cloudflare/Google/Quad9 resolvers, and shows network info for the answer. Give it an IP for a PTR + ASN lookup. |
| **4 ip** | IP intel: geolocation (db-ip), abuse confidence score and report history (AbuseIPDB), ASN/owner/prefix and reverse DNS. Leave it blank to look up your own public IP. |
| **5 whois** | Port-43 whois that follows referrals (IANA → registry → registrar, or IANA → RIR), with a parsed summary, expiry countdown, domain age and highlighted raw output. |
| **6 http** | Requests a URL and follows redirects, with a DNS / TCP / TLS / wait / download waterfall. Shows TLS version, cipher, the full cert chain and expiry (it still shows broken certs and explains what's wrong), a security-header checklist and all response headers. |
| **7 ports** | Async TCP connect scan (top 100, `all`, ranges or lists) with service names, per-port RTT, banner grabbing and a live port map. |
| **8 speed** | Download and upload over parallel streams via Cloudflare, plus idle latency, jitter, latency under load and a bufferbloat grade. |

## Usage

```sh
cargo install --git https://github.com/B33BMO/wooma

wooma                          # ping tab with 1.1.1.1 and 8.8.8.8
wooma ping 1.1.1.1 github.com
wooma trace github.com         # aliases: tracert, traceroute, mtr
wooma dns example.com          # aliases: ns, nslookup, dig
wooma ip                       # your public ip   (aliases: geo, abuse, myip)
wooma ip 185.220.101.1
wooma whois github.com
wooma http github.com          # alias: curl
wooma ports example.com 1-1024 # top | all | 1-1024 | 22,80,443   (aliases: scan, nmap)
wooma speed                    # alias: speedtest
wooma config                   # show config path and settings
```

The intro animation plays only when you launch the bare app. Direct lookups
like `wooma dns x.com` skip it, and you can turn it off for good (see below).

### Keys

| key | action |
|-----|--------|
| `1`–`8` / `tab` / `←→` | switch tool |
| `a` / `/` / `enter` | new target / query (speed: start test) |
| `↑↓` / `j k` / `pgup pgdn` | select (ping), scroll (everything else) |
| `r` | rerun (ping/trace: reset stats) |
| `d` | ping: remove target |
| `space` | ping/trace: pause |
| `n` | trace: toggle hostnames / IPs |
| `s` | dns: cycle resolver |
| `q` / `esc` | quit |

## Config

`~/.config/wooma/config.toml` (or `$XDG_CONFIG_HOME/wooma/config.toml`, or `$WOOMA_CONFIG`):

```toml
splash = false                 # skip the intro animation
abuseipdb_key = "your-api-key" # free at https://www.abuseipdb.com/account/api
```

Environment overrides: `WOOMA_NO_SPLASH=1`, `ABUSEIPDB_KEY=...`.

## Permissions

wooma speaks ICMP directly. It tries a raw socket first and falls back to the
unprivileged ICMP datagram socket.

- **macOS**: everything works without sudo.
- **Linux**: ping works unprivileged if your user is inside
  `net.ipv4.ping_group_range`. Traceroute needs a raw socket:
  `sudo setcap cap_net_raw+ep $(which wooma)` (or run with sudo).
- **Windows**: use WSL.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
