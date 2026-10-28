# Contributing

Thanks for taking a look. sshq is small on purpose and has no dependencies; please keep it
that way unless there is a strong reason.

## Development

```sh
cargo build
cargo test                                        # unit (src/lib.rs) + CLI tests (tests/cli.rs)
HOME=tests/fixtures/home cargo run -- 192.0.2.0/24
cargo fmt --all && cargo clippy --all-targets -- -D warnings
```

Module map: `lib.rs` parses config into `Entry`s, `Net` handles IP/CIDR, `Query` filters and
picks the `go` target, `render_table` formats output; `main.rs` is argument handling only.

Fixtures live in `tests/fixtures/home/.ssh/` and must use documentation addresses only
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). The CLI tests put a
fake `ssh` first on `PATH` to check `go` without connecting anywhere.

## Pull requests

- One change per PR, with a short description of the behaviour before and after.
- Add a test for parser changes, ideally a fixture line plus a CLI assertion.
- CI must be green (fmt, clippy with `-D warnings`, tests on Linux and macOS, MSRV 1.85).
- Keep comments to one line; put longer reasoning in the PR description.

## Reporting bugs

Open an issue with: sshq version (`sshq -V`), OS, the smallest config snippet that reproduces
it (redact real addresses), the command, and what you expected.
