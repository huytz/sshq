use std::env;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, exit};

use sshq::{Entry, Query, expand_tilde, parse_file, render_table, resolve};

const USAGE: &str = "sshq — search ~/.ssh/config and find which host owns an IP

usage:
  sshq                      list all hosts
  sshq <term>...            hosts matching every term (alias/hostname/user/comment)
  sshq <ip|cidr>            hosts whose HostName is that IP or inside the CIDR
  sshq go <term>...         ssh into the single match (lists if ambiguous)

options:
  -f <file>       config file (default ~/.ssh/config)
  -r              resolve DNS HostNames for IP lookup
  -a              print aliases only, one per line
  -h, --help      this help
  -V, --version   print version";

fn main() {
    let home = PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into()));
    let mut file = home.join(".ssh/config");
    let (mut resolve_dns, mut aliases_only, mut go) = (false, false, false);
    let mut terms = Vec::new();

    let mut args = env::args().skip(1).enumerate();
    while let Some((i, arg)) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            "-V" | "--version" => {
                println!("sshq {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "-r" => resolve_dns = true,
            "-a" => aliases_only = true,
            "-f" => match args.next() {
                Some((_, p)) => file = expand_tilde(&p, &home),
                None => {
                    eprintln!("-f needs a path");
                    exit(2)
                }
            },
            "go" if i == 0 => go = true,
            s if s.starts_with('-') && s.len() > 1 => {
                eprintln!("unknown option {s}\n\n{USAGE}");
                exit(2)
            }
            _ => terms.push(arg),
        }
    }

    let mut entries = parse_file(&file, &home);
    if entries.is_empty() {
        eprintln!("no hosts found in {}", file.display());
        exit(1);
    }

    let query = Query::new(&terms);
    if resolve_dns && !query.nets.is_empty() {
        for e in entries.iter_mut().filter(|e| e.is_dns()) {
            e.resolved = resolve(e.host());
        }
    }

    let hits: Vec<&Entry> = entries.iter().filter(|e| query.matches(e)).collect();
    if hits.is_empty() {
        eprintln!("no match");
        exit(1);
    }

    if go {
        if let Some(e) = query.pick(&hits) {
            eprintln!("→ ssh {}", e.aliases[0]);
            let err = Command::new("ssh").arg(&e.aliases[0]).exec();
            eprintln!("exec ssh: {err}");
            exit(1);
        }
        eprintln!("{} matches, narrow it down:", hits.len());
    }

    if aliases_only {
        for e in &hits {
            println!("{}", e.aliases[0]);
        }
    } else {
        print!("{}", render_table(&hits));
    }
    if go {
        exit(1);
    }
}
