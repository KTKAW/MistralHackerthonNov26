//! Hand-written strict JSON parser and serializer.
//!
//! Strictness and hard caps (all input is untrusted feed/config data):
//!   * total input bytes, nesting depth, single-string bytes,
//!     array items and object members are all capped;
//!   * duplicate object keys are an error;
//!   * raw control characters inside strings are an error;
//!   * numbers must match the JSON grammar exactly;
//!   * trailing garbage after the document is an error.
//!
//! The serializer escapes `"` `\` control chars, and additionally `<`, `>`
//! and `&` as `<` `>` `&` so feed text can never be
//! interpreted as HTML/script when a report is rendered downstream.

use std::collections::HashSet;
use std::fmt;

/// Hard cap on any parsed document, in bytes.
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
/// Hard cap on nesting depth.
pub const MAX_DEPTH: usize = 64;
/// Hard cap on a single decoded string, in bytes.
pub const MAX_STRING_BYTES: usize = 8 * 1024 * 1024;
/// Hard cap on array elements.
pub const MAX_ARRAY_ITEMS: usize = 250_000;
/// Hard cap on object members.
pub const MAX_OBJECT_MEMBERS: usize = 100_000;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Number kept as its exact source literal so roundtrips are lossless.
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

#[derive(Debug)]
pub struct Error {
    pub msg: String,
    pub pos: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "json error at byte {}: {}", self.pos, self.msg)
    }
}

impl std::error::Error for Error {}

fn err(pos: usize, msg: impl Into<String>) -> Error {
    Error { msg: msg.into(), pos }
}

impl Value {
    #[allow(dead_code)]
    pub fn null() -> Value {
        Value::Null
    }
    pub fn bool(b: bool) -> Value {
        Value::Bool(b)
    }
    pub fn num(n: impl Into<String>) -> Value {
        Value::Num(n.into())
    }
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }
    pub fn arr(v: Vec<Value>) -> Value {
        Value::Arr(v)
    }
    pub fn obj(v: Vec<(String, Value)>) -> Value {
        Value::Obj(v)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => n.parse::<f64>().ok(),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Num(n) => n.parse::<u64>().ok(),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Obj(o) => Some(o),
            _ => None,
        }
    }
    #[allow(dead_code)]
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// Parse a complete JSON document. Strict: see module docs.
pub fn parse(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(err(0, format!("input exceeds {} byte cap", MAX_INPUT_BYTES)));
    }
    let mut p = Parser { b: input.as_bytes(), pos: 0 };
    p.skip_ws();
    let v = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != p.b.len() {
        return Err(err(p.pos, "trailing data after document"));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), Error> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(err(self.pos, format!("expected '{}'", c as char)))
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(err(self.pos, format!("nesting exceeds depth cap {}", MAX_DEPTH)));
        }
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(Value::Str(self.parse_string()?)),
            Some(b't') => self.parse_lit("true", Value::Bool(true)),
            Some(b'f') => self.parse_lit("false", Value::Bool(false)),
            Some(b'n') => self.parse_lit("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            Some(_) => Err(err(self.pos, "unexpected character")),
            None => Err(err(self.pos, "unexpected end of input")),
        }
    }

    fn parse_lit(&mut self, lit: &str, v: Value) -> Result<Value, Error> {
        if self.b[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(v)
        } else {
            Err(err(self.pos, format!("invalid literal, expected '{}'", lit)))
        }
    }

    fn parse_number(&mut self) -> Result<Value, Error> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // int part: 0 | [1-9][0-9]*
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err(err(self.pos, "invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(err(self.pos, "invalid number: digit required after '.'"));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(err(self.pos, "invalid number: digit required in exponent"));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let raw = std::str::from_utf8(&self.b[start..self.pos]).unwrap_or("");
        Ok(Value::Num(raw.to_string()))
    }

    fn parse_string(&mut self) -> Result<String, Error> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return Err(err(self.pos, "unterminated string")),
            };
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = match self.peek() {
                        Some(e) => e,
                        None => return Err(err(self.pos, "unterminated escape")),
                    };
                    self.pos += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&cp) {
                                // high surrogate: require a low surrogate next
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                    if self.peek() == Some(b'u') {
                                        self.pos += 1;
                                        let lo = self.parse_hex4()?;
                                        if !(0xDC00..0xE000).contains(&lo) {
                                            return Err(err(self.pos, "invalid low surrogate"));
                                        }
                                        let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                        char::from_u32(c).ok_or_else(|| err(self.pos, "bad codepoint"))?
                                    } else {
                                        return Err(err(self.pos, "expected low surrogate escape"));
                                    }
                                } else {
                                    return Err(err(self.pos, "lone high surrogate"));
                                }
                            } else if (0xDC00..0xE000).contains(&cp) {
                                return Err(err(self.pos, "lone low surrogate"));
                            } else {
                                char::from_u32(cp).ok_or_else(|| err(self.pos, "bad codepoint"))?
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(err(self.pos, "invalid escape")),
                    }
                }
                0x00..=0x1F => return Err(err(self.pos - 1, "raw control character in string")),
                _ => out.push(c),
            }
            if out.len() > MAX_STRING_BYTES {
                return Err(err(self.pos, format!("string exceeds {} byte cap", MAX_STRING_BYTES)));
            }
        }
        String::from_utf8(out).map_err(|_| err(self.pos, "invalid utf-8 in string"))
    }

    fn parse_hex4(&mut self) -> Result<u32, Error> {
        if self.pos + 4 > self.b.len() {
            return Err(err(self.pos, "short \\u escape"));
        }
        let mut v: u32 = 0;
        for i in 0..4 {
            let c = self.b[self.pos + i];
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return Err(err(self.pos + i, "invalid hex digit in \\u escape")),
            };
            v = v * 16 + d;
        }
        self.pos += 4;
        Ok(v)
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, Error> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            if items.len() >= MAX_ARRAY_ITEMS {
                return Err(err(self.pos, format!("array exceeds {} item cap", MAX_ARRAY_ITEMS)));
            }
            self.skip_ws();
            items.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(err(self.pos, "expected ',' or ']' in array")),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, Error> {
        self.expect(b'{')?;
        let mut members: Vec<(String, Value)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Obj(members));
        }
        loop {
            if members.len() >= MAX_OBJECT_MEMBERS {
                return Err(err(self.pos, format!("object exceeds {} member cap", MAX_OBJECT_MEMBERS)));
            }
            self.skip_ws();
            let key = self.parse_string()?;
            if !seen.insert(key.clone()) {
                return Err(err(self.pos, format!("duplicate object key {:?}", key)));
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let val = self.parse_value(depth + 1)?;
            members.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Obj(members));
                }
                _ => return Err(err(self.pos, "expected ',' or '}' in object")),
            }
        }
    }
}

/// Compact serialization. `<`, `>`, `&` are escaped as `<` `>` `&`.
pub fn to_compact(v: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, v, false, 0);
    out
}

/// Pretty (2-space indent) serialization, same escaping rules.
pub fn to_pretty(v: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, v, true, 0);
    out
}

pub fn serialize(v: &Value, pretty: bool) -> String {
    if pretty {
        to_pretty(v)
    } else {
        to_compact(v)
    }
}

fn write_value(out: &mut String, v: &Value, pretty: bool, depth: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Num(n) => out.push_str(n),
        Value::Str(s) => escape_into(out, s),
        Value::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth + 1));
                }
                write_value(out, item, pretty, depth + 1);
            }
            if pretty {
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            out.push(']');
        }
        Value::Obj(members) => {
            if members.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth + 1));
                }
                escape_into(out, k);
                out.push(':');
                if pretty {
                    out.push(' ');
                }
                write_value(out, val, pretty, depth + 1);
            }
            if pretty {
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            out.push('}');
        }
    }
}

fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_compact() {
        let src = r#"{"a":[1,2.5,-3e2,true,false,null,"x"],"b":{"c":"d"}}"#;
        let v = parse(src).unwrap();
        assert_eq!(to_compact(&v), src);
    }

    #[test]
    fn roundtrip_pretty_parse() {
        let v = parse(&to_pretty(&parse(r#"{"k":[1,{"z":"y"}]}"#).unwrap())).unwrap();
        assert_eq!(to_compact(&v), r#"{"k":[1,{"z":"y"}]}"#);
    }

    #[test]
    fn escapes_html_chars_on_output() {
        let v = Value::str("<script>alert('x & y')</script>");
        let s = to_compact(&v);
        assert_eq!(s, "\"\\u003cscript\\u003ealert('x \\u0026 y')\\u003c/script\\u003e\"");
        // and it still parses back to the original
        match parse(&s).unwrap() {
            Value::Str(back) => assert_eq!(back, "<script>alert('x & y')</script>"),
            _ => panic!("expected string"),
        }
    }

    #[test]
    fn escapes_control_chars() {
        let v = Value::str("a\u{01}b");
        assert_eq!(to_compact(&v), "\"a\\u0001b\"");
    }

    #[test]
    fn rejects_depth_over_cap() {
        let mut s = "[".repeat(MAX_DEPTH + 2);
        s.push(']');
        s.push_str(&"]".repeat(MAX_DEPTH + 1));
        assert!(parse(&s).is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn rejects_raw_control_in_string() {
        assert!(parse("\"a\u{01}b\"").is_err());
    }

    #[test]
    fn rejects_bad_number_and_trailing() {
        assert!(parse("01").is_err());
        assert!(parse("1.").is_err());
        assert!(parse("1e").is_err());
        assert!(parse("{} x").is_err());
        assert!(parse("-").is_err());
    }

    #[test]
    fn accepts_valid_numbers() {
        for n in ["0", "-0", "12", "-12", "1.5", "-1.5e10", "2E-3", "0.25"] {
            match parse(n).unwrap() {
                Value::Num(raw) => assert_eq!(raw, n),
                _ => panic!("expected num"),
            }
        }
    }

    #[test]
    fn unicode_escapes_and_surrogates() {
        let v = parse(r#""\u0041\u00e9\ud83d\ude00""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "Aé\u{1F600}");
        assert!(parse(r#""\ud83d""#).is_err()); // lone high surrogate
        assert!(parse(r#""\ude00""#).is_err()); // lone low surrogate
    }

    #[test]
    fn rejects_array_over_cap() {
        // just over the item cap (~750KB input, well under the byte cap)
        let mut s = String::from("[");
        for i in 0..=MAX_ARRAY_ITEMS {
            if i > 0 {
                s.push(',');
            }
            s.push('0');
        }
        s.push(']');
        assert!(parse(&s).is_err());
        // just under the cap parses fine
        let mut s = String::from("[");
        for i in 0..MAX_ARRAY_ITEMS {
            if i > 0 {
                s.push(',');
            }
            s.push('0');
        }
        s.push(']');
        assert!(parse(&s).is_ok());
    }

    #[test]
    fn rejects_oversized_input() {
        // cannot allocate 32MiB+ cheaply in a unit test reliably; check the guard via length math instead
        let big = " ".repeat(MAX_INPUT_BYTES + 1);
        assert!(parse(&big).is_err());
    }
}
