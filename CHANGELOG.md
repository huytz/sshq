# Changelog

## Unreleased

## 0.1.0

First release.

- Search hosts by alias, HostName, User and comment; terms are ANDed, case-insensitive.
- Reverse lookup by IP or CIDR (IPv4 and IPv6); `-r` resolves DNS HostNames first.
- `sshq go <term>` execs ssh on a single or exact-alias match.
- `Include` with globs, first-value-wins, `Host *` and `Match` skipped.
- `-a` alias-only output, `-f` alternate config.
