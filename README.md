# sshq

**Search your `~/.ssh/config` and find which host owns an IP.**

`ssh -G` goes alias → address. sshq goes the other way too: give it an IP or a CIDR and it
tells you which `Host` entries point there. Give it words and it filters hosts by alias,
HostName, User and the comment above the block. Rust, standard library only, no dependencies.

```console
$ sshq 192.0.2.0/24
ALIAS          HOSTNAME     USER    PORT  JUMP  COMMENT
stg-api        192.0.2.200  ubuntu  -     -     staging
prod-web-1 +1  192.0.2.10   deploy  -     -     prod
prod-web-2     192.0.2.11   deploy  -     -     -

$ sshq prod db
ALIAS      HOSTNAME       USER      PORT  JUMP     COMMENT
prod-db-1  198.51.100.20  postgres  2222  bastion  -

$ sshq go web-2          # exactly one match → exec ssh prod-web-2
```

## Install

Download a binary from [Releases](https://github.com/huytz/sshq/releases) (Linux and macOS,
x86_64 and arm64), or build from source:

```sh
cargo install --git https://github.com/huytz/sshq
```

Needs Rust 1.85+ to build. Unix only (`go` uses `exec`).

## Usage

```
sshq                      list all hosts
sshq <term>...            hosts matching every term (alias/hostname/user/comment)
sshq <ip|cidr>            hosts whose HostName is that IP or inside the CIDR
sshq go <term>...         ssh into the single match (lists if ambiguous)

-f <file>       config file (default ~/.ssh/config)
-r              resolve DNS HostNames for IP lookup
-a              print aliases only, one per line
-h, --help      help
-V, --version   version
```

- Terms are ANDed and case-insensitive. A term that parses as an IP or `ip/prefix` (IPv4 or
  IPv6) is an address filter; anything else is a substring match.
- `-r` resolves non-IP HostNames through the system resolver so `sshq -r 203.0.113.5` finds
  hosts configured by DNS name. Without it, only literal IPs are compared.
- `go` execs `ssh <alias>` when there is one hit, or one hit whose alias equals a term
  (`go node_3` picks `node_3` over `node_30`). Otherwise it prints the matches and exits 1.
- `-a` makes output easy to pipe: `sshq -a prod | xargs -n1 -I{} ssh {} uptime`.
- Exit codes: `0` matches, `1` no match or no hosts, `2` bad arguments.

## What it reads

- `Host` blocks with `HostName`, `User`, `Port`, `ProxyJump`; first value wins, like ssh.
- `Include`, with `~` and `*`/`?` globs; relative paths resolve against `~/.ssh`.
- Comment lines directly above a `Host` line become its comment; banner decoration such as
  `# ── prod ──` is trimmed to `prod`. A blank line detaches a comment.
- Patterns (`*`, `?`, `!`) in a `Host` line are dropped; a block with only patterns
  (`Host *`) is skipped. `Match` blocks are ignored.

## Limits

- Settings inherited from `Host *` or `Match` are not applied; use `ssh -G <alias>` for the
  fully resolved view of one host.
- `Include` inside a `Host` block is read but its hosts are listed before that block.

[CONTRIBUTING](CONTRIBUTING.md) · [SECURITY](SECURITY.md) · [CHANGELOG](CHANGELOG.md) · [MIT](LICENSE)
