//! Parse OpenSSH client config and query hosts by text or IP/CIDR.

use std::fs;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

/// Maximum Include nesting, same limit as OpenSSH.
const MAX_DEPTH: u8 = 16;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Entry {
    pub aliases: Vec<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<String>,
    pub jump: Option<String>,
    pub comment: Option<String>,
    pub resolved: Vec<IpAddr>,
}

impl Entry {
    /// Target host: HostName if set, else the first alias (what ssh would dial).
    pub fn host(&self) -> &str {
        self.hostname.as_deref().unwrap_or(&self.aliases[0])
    }

    /// True when HostName is a DNS name rather than a literal IP.
    pub fn is_dns(&self) -> bool {
        self.host().parse::<IpAddr>().is_err()
    }

    /// Literal IP of the target, or whatever `-r` resolved it to.
    pub fn ips(&self) -> Vec<IpAddr> {
        match self.host().parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self.resolved.clone(),
        }
    }

    fn haystack(&self) -> String {
        let fields = [
            self.aliases.join(" "),
            self.hostname.clone().unwrap_or_default(),
            self.user.clone().unwrap_or_default(),
            self.comment.clone().unwrap_or_default(),
        ];
        fields.join(" ").to_lowercase()
    }
}

/// Expand a leading `~/` against `home`.
pub fn expand_tilde(p: &str, home: &Path) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(p),
    }
}

/// Glob match supporting only `*` and `?`, enough for ssh Include patterns.
pub fn wild(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => wild(&pat[1..], s) || (!s.is_empty() && wild(pat, &s[1..])),
        (Some(b'?'), Some(_)) => wild(&pat[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => wild(&pat[1..], &s[1..]),
        _ => false,
    }
}

fn expand_include(arg: &str, home: &Path) -> Vec<PathBuf> {
    let p = expand_tilde(arg, home);
    let p = if p.is_absolute() {
        p
    } else {
        home.join(".ssh").join(p)
    };
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !name.contains(['*', '?']) {
        return vec![p];
    }
    let dir = p.parent().unwrap_or(Path::new("."));
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|f| {
            f.file_name()
                .is_some_and(|n| wild(name.as_bytes(), n.as_encoded_bytes()))
        })
        .collect();
    out.sort();
    out
}

/// Parse a config file and everything it Includes; unreadable files yield nothing.
pub fn parse_file(path: &Path, home: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    parse_into(path, home, &mut out, 0);
    out
}

fn parse_into(path: &Path, home: &Path, out: &mut Vec<Entry>, depth: u8) {
    if let Ok(text) = fs::read_to_string(path) {
        parse_text(&text, home, out, depth);
    }
}

/// Parse config text; Include paths resolve relative to `home/.ssh`.
pub fn parse_text(text: &str, home: &Path, out: &mut Vec<Entry>, depth: u8) {
    let mut cur: Option<Entry> = None;
    let mut pending_comment: Vec<String> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            pending_comment.clear();
            continue;
        }
        if let Some(c) = line.strip_prefix('#') {
            // Strip banner decoration like `── prod ──` so only the label remains.
            let c = c.trim_matches(|ch: char| ch.is_whitespace() || "─━-=#*".contains(ch));
            if !c.is_empty() {
                pending_comment.push(c.to_string());
            }
            continue;
        }
        let (key, val) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (
                k.to_lowercase(),
                v.trim_start_matches(|c: char| c.is_whitespace() || c == '=')
                    .trim(),
            ),
            None => (line.to_lowercase(), ""),
        };
        let val = val.trim_matches('"');
        match key.as_str() {
            "host" => {
                out.extend(cur.take());
                let aliases: Vec<String> = val
                    .split_whitespace()
                    .filter(|a| !a.contains(['*', '?', '!']))
                    .map(String::from)
                    .collect();
                if !aliases.is_empty() {
                    let comment = (!pending_comment.is_empty()).then(|| pending_comment.join(" "));
                    cur = Some(Entry {
                        aliases,
                        comment,
                        ..Default::default()
                    });
                }
                pending_comment.clear();
            }
            // Match blocks are conditional; treat them as the end of the previous Host.
            "match" => out.extend(cur.take()),
            "include" if depth < MAX_DEPTH => {
                for f in val.split_whitespace().flat_map(|a| expand_include(a, home)) {
                    parse_into(&f, home, out, depth + 1);
                }
            }
            _ => {
                let Some(e) = cur.as_mut() else { continue };
                let slot = match key.as_str() {
                    "hostname" => &mut e.hostname,
                    "user" => &mut e.user,
                    "port" => &mut e.port,
                    "proxyjump" => &mut e.jump,
                    _ => continue,
                };
                // ssh uses the first value obtained, so keep the earliest.
                slot.get_or_insert_with(|| val.to_string());
            }
        }
    }
    out.extend(cur);
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    /// Parse `ip` or `ip/prefix`; returns None for anything else.
    pub fn parse(s: &str) -> Option<Net> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip.parse::<IpAddr>().ok()?, Some(p.parse::<u8>().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Net { addr: ip, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let mask = |bits: u32| {
            if self.prefix == 0 {
                0
            } else {
                u128::MAX << (bits - self.prefix as u32)
            }
        };
        match (ip, self.addr) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let m = mask(32) as u32;
                u32::from(*a) & m == u32::from(b) & m
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let m = mask(128);
                u128::from(*a) & m == u128::from(b) & m
            }
            _ => false,
        }
    }
}

/// Search terms split into text words (AND, case-insensitive) and IP/CIDR filters (AND).
#[derive(Debug, Default)]
pub struct Query {
    pub words: Vec<String>,
    pub nets: Vec<Net>,
}

impl Query {
    pub fn new<S: AsRef<str>>(terms: &[S]) -> Query {
        let mut q = Query::default();
        for t in terms {
            match Net::parse(t.as_ref()) {
                Some(n) => q.nets.push(n),
                None => q.words.push(t.as_ref().to_lowercase()),
            }
        }
        q
    }

    pub fn matches(&self, e: &Entry) -> bool {
        let hay = e.haystack();
        let ips = e.ips();
        self.words.iter().all(|w| hay.contains(w.as_str()))
            && self
                .nets
                .iter()
                .all(|n| ips.iter().any(|ip| n.contains(ip)))
    }

    /// Single target for `go`: the only hit, or the only hit whose alias equals a word.
    pub fn pick<'a>(&self, hits: &[&'a Entry]) -> Option<&'a Entry> {
        if let [one] = hits {
            return Some(one);
        }
        let exact: Vec<&&Entry> = hits
            .iter()
            .filter(|e| {
                e.aliases
                    .iter()
                    .any(|a| self.words.contains(&a.to_lowercase()))
            })
            .collect();
        match exact.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }
}

/// System resolver lookup; empty on failure.
pub fn resolve(host: &str) -> Vec<IpAddr> {
    (host, 22)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// Aligned table with header; DNS HostNames show resolved IPs when known.
pub fn render_table(rows: &[&Entry]) -> String {
    let dash = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".into());
    let cells: Vec<[String; 6]> = rows
        .iter()
        .map(|e| {
            let alias = match e.aliases.len() {
                1 => e.aliases[0].clone(),
                n => format!("{} +{}", e.aliases[0], n - 1),
            };
            let mut host = e.host().to_string();
            if e.is_dns() && !e.resolved.is_empty() {
                let ips: Vec<String> = e.resolved.iter().map(|i| i.to_string()).collect();
                host = format!("{host} ({})", ips.join(","));
            }
            [
                alias,
                host,
                dash(&e.user),
                dash(&e.port),
                dash(&e.jump),
                dash(&e.comment),
            ]
        })
        .collect();
    let head = ["ALIAS", "HOSTNAME", "USER", "PORT", "JUMP", "COMMENT"].map(String::from);
    let mut w = [0usize; 6];
    for row in std::iter::once(&head).chain(&cells) {
        for (i, v) in row.iter().enumerate() {
            w[i] = w[i].max(v.chars().count());
        }
    }
    let mut out = String::new();
    for row in std::iter::once(&head).chain(&cells) {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, v)| format!("{v:<0$}", w[i]))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Vec<Entry> {
        let mut out = Vec::new();
        parse_text(text, Path::new("/nonexistent"), &mut out, 0);
        out
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_basic_fields() {
        let e = parse(
            "Host web\n  HostName 192.0.2.10\n  User deploy\n  Port 2222\n  ProxyJump bastion\n",
        );
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].aliases, ["web"]);
        assert_eq!(e[0].hostname.as_deref(), Some("192.0.2.10"));
        assert_eq!(e[0].user.as_deref(), Some("deploy"));
        assert_eq!(e[0].port.as_deref(), Some("2222"));
        assert_eq!(e[0].jump.as_deref(), Some("bastion"));
    }

    #[test]
    fn keywords_are_case_insensitive_and_accept_equals() {
        let e = parse("HOST a\n hostname=192.0.2.1\n USER = root\n");
        assert_eq!(e[0].hostname.as_deref(), Some("192.0.2.1"));
        assert_eq!(e[0].user.as_deref(), Some("root"));
    }

    #[test]
    fn first_value_wins() {
        let e = parse("Host a\n HostName 192.0.2.1\n HostName 192.0.2.2\n");
        assert_eq!(e[0].hostname.as_deref(), Some("192.0.2.1"));
    }

    #[test]
    fn quoted_values_are_unquoted() {
        let e = parse("Host a\n User \"ops team\"\n");
        assert_eq!(e[0].user.as_deref(), Some("ops team"));
    }

    #[test]
    fn wildcard_hosts_are_skipped_and_patterns_dropped() {
        let e = parse("Host *\n User root\nHost db-* !db-old db1\n HostName 192.0.2.5\n");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].aliases, ["db1"]);
        assert_eq!(e[0].user, None);
    }

    #[test]
    fn match_block_ends_host() {
        let e = parse("Host a\n User x\nMatch host b\n User y\n");
        assert_eq!(e[0].user.as_deref(), Some("x"));
    }

    #[test]
    fn comments_attach_to_next_host_and_reset_on_blank() {
        let e = parse("# ── prod ──\nHost a\n\n# orphan\n\nHost b\n# tier one\nHost c\n");
        assert_eq!(e[0].comment.as_deref(), Some("prod"));
        assert_eq!(e[1].comment, None);
        assert_eq!(e[2].comment.as_deref(), Some("tier one"));
    }

    #[test]
    fn host_falls_back_to_alias() {
        let e = parse("Host example.org\n User x\n");
        assert_eq!(e[0].host(), "example.org");
        assert!(e[0].is_dns());
    }

    #[test]
    fn wild_glob() {
        assert!(wild(b"*.conf", b"a.conf"));
        assert!(wild(b"h?st", b"host"));
        assert!(wild(b"*", b""));
        assert!(!wild(b"*.conf", b"a.conf.bak"));
        assert!(!wild(b"h?st", b"hst"));
    }

    #[test]
    fn tilde_expansion() {
        let h = Path::new("/home/u");
        assert_eq!(expand_tilde("~/x", h), PathBuf::from("/home/u/x"));
        assert_eq!(expand_tilde("/abs", h), PathBuf::from("/abs"));
    }

    #[test]
    fn net_parse() {
        assert_eq!(Net::parse("192.0.2.1").unwrap().prefix, 32);
        assert_eq!(Net::parse("2001:db8::/32").unwrap().prefix, 32);
        assert_eq!(Net::parse("2001:db8::1").unwrap().prefix, 128);
        assert!(Net::parse("192.0.2.0/33").is_none());
        assert!(Net::parse("192.0.2.0/x").is_none());
        assert!(Net::parse("web").is_none());
    }

    #[test]
    fn net_contains() {
        let n = Net::parse("198.51.100.0/24").unwrap();
        assert!(n.contains(&ip("198.51.100.7")));
        assert!(!n.contains(&ip("198.51.101.7")));
        assert!(
            Net::parse("0.0.0.0/0")
                .unwrap()
                .contains(&ip("203.0.113.9"))
        );
        assert!(
            Net::parse("2001:db8::/32")
                .unwrap()
                .contains(&ip("2001:db8:1::5"))
        );
        assert!(!n.contains(&ip("2001:db8::1")));
    }

    #[test]
    fn query_words_and_nets() {
        let e = parse(
            "# edge\nHost web-1\n HostName 192.0.2.10\n User deploy\nHost db-1\n HostName 198.51.100.4\n",
        );
        let hits = |terms: &[&str]| -> Vec<String> {
            let q = Query::new(terms);
            e.iter()
                .filter(|x| q.matches(x))
                .map(|x| x.aliases[0].clone())
                .collect()
        };
        assert_eq!(hits(&[]), ["web-1", "db-1"]);
        assert_eq!(hits(&["WEB"]), ["web-1"]);
        assert_eq!(hits(&["edge", "deploy"]), ["web-1"]);
        assert_eq!(hits(&["192.0.2.0/24"]), ["web-1"]);
        assert_eq!(hits(&["198.51.100.4"]), ["db-1"]);
        assert!(hits(&["web", "198.51.100.4"]).is_empty());
    }

    #[test]
    fn dns_host_matches_net_only_after_resolve() {
        let mut e = parse("Host svc\n HostName svc.example\n").remove(0);
        let q = Query::new(&["203.0.113.0/24"]);
        assert!(!q.matches(&e));
        e.resolved = vec![ip("203.0.113.20")];
        assert!(q.matches(&e));
    }

    #[test]
    fn pick_prefers_exact_alias() {
        let e = parse("Host node_3\nHost node_30\n");
        let hits: Vec<&Entry> = e.iter().collect();
        assert_eq!(
            Query::new(&["node_3"]).pick(&hits).unwrap().aliases[0],
            "node_3"
        );
        assert!(Query::new(&["node"]).pick(&hits).is_none());
        assert_eq!(
            Query::new(&["x"]).pick(&hits[..1]).unwrap().aliases[0],
            "node_3"
        );
    }

    #[test]
    fn table_layout() {
        let mut e = parse(
            "# c\nHost a b c\n HostName svc.example\nHost longer\n HostName 192.0.2.1\n User u\n",
        );
        e[0].resolved = vec![ip("203.0.113.1")];
        let t = render_table(&e.iter().collect::<Vec<_>>());
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("ALIAS   HOSTNAME"));
        assert!(lines[1].starts_with("a +2    svc.example (203.0.113.1)"));
        assert!(lines[1].ends_with("  c"));
        assert!(lines[2].starts_with("longer  192.0.2.1"));
        assert!(t.lines().all(|l| l == l.trim_end()));
    }
}
