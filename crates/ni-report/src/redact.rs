//! Redaction of a serialised report.

use crate::ExportOptions;
use ni_core::addr;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;

/// Keys whose string values are file system paths.
const PATH_KEYS: &[&str] = &["path"];
/// Keys whose values are addresses of this machine.
const LOCAL_KEYS: &[&str] = &["localAddr", "local"];
/// Keys with free text written by the user.
const NOTE_KEYS: &[&str] = &["note", "label"];

#[derive(Default)]
struct Pseudonyms {
    map: HashMap<IpAddr, String>,
    counters: HashMap<(String, bool), usize>,
}

impl Pseudonyms {
    fn name(&mut self, ip: IpAddr, kind: &str) -> String {
        if let Some(n) = self.map.get(&ip) {
            return n.clone();
        }
        let c = self
            .counters
            .entry((kind.to_string(), ip.is_ipv4()))
            .or_insert(0);
        *c += 1;
        let n = format!("{kind}-{}-{c}", if ip.is_ipv4() { "ipv4" } else { "ipv6" });
        self.map.insert(ip, n.clone());
        n
    }
}

pub fn apply(v: &mut Value, o: &ExportOptions) {
    let mut p = Pseudonyms::default();
    // First pass: local addresses get "local-" names, so the same address
    // appearing in free text later maps to the same pseudonym.
    if o.redact_local_addresses {
        collect_local(v, &mut p);
    }
    walk(v, None, o, &mut p);
}

fn collect_local(v: &Value, p: &mut Pseudonyms) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                if LOCAL_KEYS.contains(&k.as_str()) {
                    if let Some(ip) = val.as_str().and_then(parse_ip_or_sock) {
                        if !ip.is_unspecified() {
                            p.name(ip, "local");
                        }
                    }
                }
                collect_local(val, p);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_local(x, p)),
        _ => {}
    }
}

fn parse_ip_or_sock(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<std::net::SocketAddr>().ok().map(|sa| sa.ip()))
}

fn walk(v: &mut Value, key: Option<&str>, o: &ExportOptions, p: &mut Pseudonyms) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                walk(val, Some(k.as_str()), o, p);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| walk(x, key, o, p)),
        Value::String(s) => {
            let k = key.unwrap_or("");
            if !o.include_notes && NOTE_KEYS.contains(&k) {
                if !s.is_empty() {
                    *s = "[скрыто]".into();
                }
                return;
            }
            if o.redact_paths && (PATH_KEYS.contains(&k) || looks_like_path(s)) {
                *s = file_name(s);
            }
            *s = redact_text(s, o, p);
        }
        _ => {}
    }
}

fn looks_like_path(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || s.starts_with("\\\\")
}

fn file_name(s: &str) -> String {
    if !looks_like_path(s) {
        return s.to_string();
    }
    let name = s.rsplit(['\\', '/']).next().unwrap_or("");
    format!("…\\{name}")
}

/// Replaces sensitive IP addresses inside arbitrary text.
fn redact_text(s: &str, o: &ExportOptions, p: &mut Pseudonyms) -> String {
    if !o.redact_private_ips && !o.redact_local_addresses {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String, p: &mut Pseudonyms| {
        if token.is_empty() {
            return;
        }
        // Trailing ':' or '.' belong to the sentence or the port separator.
        let trimmed = token.trim_end_matches([':', '.']);
        let tail = &token[trimmed.len()..];
        match replacement(trimmed, o, p) {
            Some(r) => {
                out.push_str(&r);
                out.push_str(tail);
            }
            None => {
                // "1.2.3.4:443" — split off the port.
                if let Some((ip, port)) =
                    trimmed.rsplit_once(':').filter(|(ip, _)| ip.contains('.'))
                {
                    if let Some(r) = replacement(ip, o, p) {
                        out.push_str(&r);
                        out.push(':');
                        out.push_str(port);
                        out.push_str(tail);
                        token.clear();
                        return;
                    }
                }
                out.push_str(token);
            }
        }
        token.clear();
    };
    for c in s.chars() {
        if c.is_ascii_hexdigit() || c == '.' || c == ':' {
            token.push(c);
        } else {
            flush(&mut token, &mut out, p);
            out.push(c);
        }
    }
    flush(&mut token, &mut out, p);
    out
}

fn replacement(t: &str, o: &ExportOptions, p: &mut Pseudonyms) -> Option<String> {
    let ip: IpAddr = t.parse().ok()?;
    let ip_n = addr::normalize(ip);
    if let Some(n) = p.map.get(&ip).or_else(|| p.map.get(&ip_n)) {
        return Some(n.clone());
    }
    if o.redact_private_ips && addr::scope(&ip_n).is_sensitive() {
        return Some(p.name(ip_n, "private"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn opts() -> ExportOptions {
        ExportOptions::default()
    }

    #[test]
    fn redacts_private_and_local_keeps_public() {
        let mut v = json!({
            "endpoints": [
                {"localAddr": "203.0.113.50", "remoteAddr": "192.168.1.1", "remotePort": 53},
                {"localAddr": "10.0.0.2", "remoteAddr": "162.159.130.234"}
            ],
            "text": "Сокет к 192.168.1.1:53 и 162.159.130.234:443, локальный 203.0.113.50.",
            "v6": "fe80::1",
            "public6": "2606:4700::6810:1"
        });
        apply(&mut v, &opts());
        let s = v.to_string();
        assert!(!s.contains("192.168.1.1"), "{s}");
        assert!(!s.contains("10.0.0.2"));
        assert!(
            !s.contains("203.0.113.50"),
            "public local address must be hidden"
        );
        assert!(!s.contains("fe80::1"));
        assert!(s.contains("162.159.130.234"));
        assert!(s.contains("2606:4700::6810:1"));
        // Same address, same pseudonym everywhere.
        assert_eq!(v["endpoints"][0]["remoteAddr"], "private-ipv4-1");
        assert!(v["text"].as_str().unwrap().contains("private-ipv4-1:53"));
        assert!(v["text"].as_str().unwrap().contains(&format!(
            "{}.",
            v["endpoints"][0]["localAddr"].as_str().unwrap()
        )));
    }

    #[test]
    fn redacts_paths_and_notes() {
        let mut v = json!({
            "path": "C:\\Users\\alice\\AppData\\Local\\Discord\\app-1.0\\Discord.exe",
            "observations": [{"text": "D:\\Games\\Steam\\steam.exe"}],
            "note": "мой пароль не тут",
            "kind": {"label": "маркер"}
        });
        apply(&mut v, &opts());
        assert_eq!(v["path"], "…\\Discord.exe");
        assert_eq!(v["observations"][0]["text"], "…\\steam.exe");
        assert_eq!(v["note"], "[скрыто]");
        assert_eq!(v["kind"]["label"], "[скрыто]");
    }

    #[test]
    fn disabled_redaction_keeps_everything() {
        let o = ExportOptions {
            redact_private_ips: false,
            redact_local_addresses: false,
            redact_paths: false,
            include_notes: true,
            include_events: true,
        };
        let mut v = json!({"a": "10.0.0.1", "path": "C:\\x\\y.exe", "note": "n"});
        let before = v.clone();
        apply(&mut v, &o);
        assert_eq!(v, before);
    }

    #[test]
    fn non_ip_hex_text_is_untouched() {
        let mut v = json!({"t": "sha deadbeef, time 12:30:45, ratio 1.5, id abc:def"});
        let before = v.clone();
        apply(&mut v, &opts());
        assert_eq!(v, before);
    }
}
