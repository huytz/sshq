# Security

## Model

- sshq only reads the ssh config file you point it at and the files it `Include`s. It never
  writes files, never reads private keys or `known_hosts`, and has no telemetry.
- The only network activity is DNS lookups through the system resolver, and only with `-r`.
- `sshq go` replaces itself with `ssh <alias>` found on `$PATH`; the alias comes from your own
  config and is passed as a single argument, never through a shell.

## Out of scope

- Malicious content in your own ssh config: sshq trusts it as much as `ssh` does.

## Reporting a vulnerability

Please do not open a public issue. Email the maintainer (see the GitHub profile of
[@huytz](https://github.com/huytz)) with a description and reproduction steps. You should get a
reply within a week.
