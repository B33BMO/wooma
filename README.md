# wooma

A terminal toolkit for network diagnostics, written in Rust. Ping, traceroute,
DNS, IP intel, whois, HTTP timing, port scanning and a speed test in one TUI.

## Tools

| tab | what it does |
|-----|--------------|
| **1 ping** | Ping many hosts at once. Live up/down state with flap count, loss %, min/avg/max, stddev, jitter, a scrolling latency chart and a status-page style timeline. |
| **2 trace** | Continuous mtr-style traceroute. Per-hop loss, last/avg/best/worst/stdev, reverse DNS, ASN + owner + country (via Team Cymru), and ECMP detection. |
| **3 dns** | Queries A, AAAA, CNAME, MX, NS, TXT, SOA and CAA in parallel with TTLs and per-type timing, races system/Cloudflare/Google/Quad9 resolvers, and shows network info for the answer. Give it an IP for a PTR + ASN lookup. |
| **4 ip** | IP intel: geolocation (db-ip), abuse confidence score and report history (AbuseIPDB), ASN/owner/prefix and reverse DNS. Leave it blank to look up your own public IP. |
| **5 whois** | Port-43 whois that follows referrals (IANA → registry → registrar, or IANA → RIR), with a parsed summary, expiry countdown, domain age and highlighted raw output. |
| **6 http** | Requests a URL and follows redirects, with a DNS / TCP / TLS / wait / download waterfall. Shows TLS version, cipher, the full cert chain and expiry (it still shows broken certs and explains what's wrong), a security-header checklist and all response headers. |
| **7 ports** | Async TCP connect scan (top 100, `all`, ranges or lists) with service names, per-port RTT, banner grabbing and a live port map. |
| **8 speed** | Download and upload over parallel streams via Cloudflare, plus idle latency, jitter, latency under load and a bufferbloat grade. |

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/B33BMO/wooma/main/install.sh | sh
```

This downloads a prebuilt static binary for your platform (Linux x86_64 /
arm64, macOS Intel / Apple Silicon) into `~/.local/bin`, checks its checksum,
and on Linux offers to set up ICMP access, asking for sudo; see
[Permissions](#permissions). On other platforms it falls back to building from
source with cargo.

Environment settings, set on the `sh` side of the pipe:

| variable | effect |
|----------|--------|
| `WOOMA_INSTALL_DIR=dir` | install somewhere other than `~/.local/bin` |
| `WOOMA_VERSION=v0.1.0` | a specific release instead of the latest |
| `WOOMA_ICMP=sysctl\|setcap\|skip` | pick the permission fix without asking |

Prebuilt binaries are also on the [releases page](https://github.com/B33BMO/wooma/releases).
With Rust installed you can build it yourself:
`cargo install --git https://github.com/B33BMO/wooma --locked`

## Usage

```sh
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
abuseipdb_key = "your-api-key" # free at https://www.abuseipdb.com/account/api
```

Environment overrides: `ABUSEIPDB_KEY=...`.

## Permissions

wooma speaks ICMP directly. It tries a raw socket first and falls back to the
unprivileged ICMP datagram socket. Run `wooma config` to see which one you get.

- **macOS**: everything works without sudo.
- **Linux**: ping and traceroute both work unprivileged if your group is inside
  `net.ipv4.ping_group_range`. Most systemd distros allow this by default; WSL
  and some minimal images don't (`cat /proc/sys/net/ipv4/ping_group_range`
  prints `1 0`). Either open it up for everyone:

  ```sh
  echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/99-ping.conf
  sudo sysctl --system
  ```

  or give just the binary raw sockets (redo this after every reinstall; the
  install script does it for you):

  ```sh
  sudo setcap cap_net_raw+ep "$(which wooma)"
  ```
- **Windows**: use WSL.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
