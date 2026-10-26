//! A federation's successor notice, as Fedimint's meta module carries it.
//!
//! Each guardian submits the whole meta object, and it becomes consensus only
//! once a threshold of guardians submit the same bytes (fedimint 0.11
//! `fedimint-meta-server`). So this builds the object in one canonical form:
//! what the federation publishes now, plus the three fields a successor notice
//! sets, keys sorted at every level, no whitespace. Guardians who run it with
//! the same inputs submit identical bytes.
//!
//! The values are encoded as upstream's guardian dashboard writes them
//! (`fedimint-server-ui` meta module, v0.11.4): `federation_successor` and
//! `welcome_message` as strings, `federation_expiry_timestamp` as a string of
//! base-10 Unix seconds (docs/meta_fields/).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

/// The three fields a successor notice sets.
#[derive(Debug, Clone)]
pub struct SuccessorNotice {
    /// The successor's invite code (`fed1…`, bech32m).
    pub invite: String,
    /// Unix seconds after which this federation stops.
    pub expires_at: u64,
    /// What happened to the funds and what happens to anything left.
    pub message: String,
}

/// CLI entrypoint · print the meta object with the successor notice, for each
/// guardian to submit unchanged.
pub fn successor(
    invite: String,
    expires: String,
    message: String,
    current: Option<String>,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before 1970")?
        .as_secs();
    let current_json = match current.as_deref() {
        None => None,
        Some("-") => Some(std::io::read_to_string(std::io::stdin()).context("reading stdin")?),
        Some(path) => {
            Some(std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?)
        }
    };
    let notice = SuccessorNotice {
        invite,
        expires_at: parse_expiry(&expires)?,
        message,
    };
    let object = successor_meta(current_json.as_deref(), &notice, now)?;
    println!("{object}");
    eprintln!(
        "Each guardian submits this line unchanged, byte for byte; it becomes the \
         federation's meta once a threshold has:\n  fedimint-cli --our-id <your peer id> \
         --password <admin password> module meta submit {}",
        shell_quote(&object)
    );
    Ok(())
}

/// The meta object with the successor notice set, in canonical form.
///
/// `current` is what `fedimint-cli module meta get` prints (`null`, or
/// `{"revision":…,"value":{…}}`), or the bare object. Its other keys are kept.
pub fn successor_meta(current: Option<&str>, notice: &SuccessorNotice, now: u64) -> Result<String> {
    check_invite(&notice.invite)?;
    if notice.expires_at <= now {
        bail!("the expiry {} is not in the future", notice.expires_at);
    }
    if notice.message.trim().is_empty() {
        bail!("the message is empty: say where the funds went and what happens to anything left");
    }
    let mut object = match current.map(str::trim).filter(|s| !s.is_empty()) {
        None => serde_json::Map::new(),
        Some(text) => current_object(text)?,
    };
    object.insert(
        "federation_successor".into(),
        Value::String(notice.invite.clone()),
    );
    object.insert(
        "federation_expiry_timestamp".into(),
        Value::String(notice.expires_at.to_string()),
    );
    object.insert(
        "welcome_message".into(),
        Value::String(notice.message.clone()),
    );
    let mut out = String::new();
    canonical(&Value::Object(object), &mut out)?;
    Ok(out)
}

fn current_object(text: &str) -> Result<serde_json::Map<String, Value>> {
    let parsed: Value = serde_json::from_str(text).context("the current meta is not JSON")?;
    let inner = match parsed {
        Value::Null => return Ok(serde_json::Map::new()),
        // `fedimint-cli module meta get` wraps the value with its revision.
        Value::Object(mut o)
            if o.len() == 2 && o.contains_key("revision") && o.contains_key("value") =>
        {
            o.remove("value").unwrap_or(Value::Null)
        }
        other => other,
    };
    match inner {
        Value::Null => Ok(serde_json::Map::new()),
        Value::Object(o) => Ok(o),
        _ => bail!("the current meta is not a JSON object"),
    }
}

/// One POSIX shell word, so a message with an apostrophe survives being pasted.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Keys sorted at every level and no whitespace, whatever order the input had.
fn canonical(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k)?);
                out.push(':');
                canonical(&o[k.as_str()], out)?;
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out)?;
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other)?),
    }
    Ok(())
}

/// Unix seconds, or a date `YYYY-MM-DD` read as midnight UTC.
pub fn parse_expiry(s: &str) -> Result<u64> {
    let s = s.trim();
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().context("the expiry is not a number of seconds");
    }
    let bad = || anyhow!("the expiry {s:?} is neither Unix seconds nor a date YYYY-MM-DD");
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return Err(bad());
    }
    let (y, m, d): (i64, u32, u32) = (
        parts[0].parse().map_err(|_| bad())?,
        parts[1].parse().map_err(|_| bad())?,
        parts[2].parse().map_err(|_| bad())?,
    );
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&m) || d == 0 || d > days_in[(m - 1) as usize] || y < 1970 {
        return Err(bad());
    }
    Ok((days_from_civil(y, m, d) * 86_400) as u64)
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// A Fedimint invite code: bech32m with the human part `fed1`, as
/// `fedimint_core::invite_code::InviteCode` encodes it.
pub fn check_invite(invite: &str) -> Result<()> {
    let bad = |why: &str| anyhow!("not a Fedimint invite code ({why})");
    if invite.bytes().any(|b| b.is_ascii_uppercase())
        && invite.bytes().any(|b| b.is_ascii_lowercase())
    {
        return Err(bad("mixed case"));
    }
    let lower = invite.to_ascii_lowercase();
    let sep = lower.rfind('1').ok_or_else(|| bad("no separator"))?;
    let (hrp, data) = (&lower[..sep], &lower[sep + 1..]);
    if hrp != "fed1" {
        return Err(bad("it does not start fed1"));
    }
    // The federation id alone is 32 bytes, so a real code is far longer than its checksum.
    if data.len() <= 6 + 52 {
        return Err(bad("too short"));
    }
    let mut values: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|c| c & 31));
    for c in data.bytes() {
        let v = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| bad("a character outside bech32"))?;
        values.push(v as u8);
    }
    if polymod(&values) != BECH32M_CONST {
        return Err(bad("the checksum does not match"));
    }
    Ok(())
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fedimint v0.11.4, fedimint-core/src/invite_code.rs `test_invite_code_to_from_string`.
    const UPSTREAM_INVITE: &str = "fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pm";
    const NOW: u64 = 1_793_000_000;

    fn notice() -> SuccessorNotice {
        SuccessorNotice {
            invite: UPSTREAM_INVITE.into(),
            expires_at: 1_795_000_000,
            message: "Moved to the successor federation.".into(),
        }
    }

    /// A bech32m string with a valid checksum, for codes that must fail on
    /// something other than the checksum.
    fn encode(hrp: &str, data: &[u8]) -> String {
        let mut values: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
        values.push(0);
        values.extend(hrp.bytes().map(|c| c & 31));
        values.extend_from_slice(data);
        values.extend([0u8; 6]);
        let m = polymod(&values) ^ BECH32M_CONST;
        let mut out = format!("{hrp}1");
        for &d in data {
            out.push(CHARSET[d as usize] as char);
        }
        for i in 0..6 {
            out.push(CHARSET[((m >> (5 * (5 - i))) & 31) as usize] as char);
        }
        out
    }

    fn upstream_data() -> Vec<u8> {
        let data = &UPSTREAM_INVITE[5..UPSTREAM_INVITE.len() - 6];
        data.bytes()
            .map(|c| CHARSET.iter().position(|&x| x == c).unwrap() as u8)
            .collect()
    }

    #[test]
    fn the_test_encoder_reproduces_upstream() {
        assert_eq!(encode("fed1", &upstream_data()), UPSTREAM_INVITE);
    }

    #[test]
    fn a_valid_checksum_under_another_prefix_or_too_short_is_refused() {
        let other = encode("lnbc", &upstream_data());
        let err = check_invite(&other).unwrap_err().to_string();
        assert!(err.contains("fed1"), "{err}");
        let short = encode("fed1", &upstream_data()[..20]);
        let err = check_invite(&short).unwrap_err().to_string();
        assert!(err.contains("too short"), "{err}");
    }

    #[test]
    fn upstream_invite_passes() {
        check_invite(UPSTREAM_INVITE).unwrap();
        check_invite(&UPSTREAM_INVITE.to_ascii_uppercase()).unwrap();
    }

    #[test]
    fn a_changed_character_fails_the_checksum() {
        let mut s = UPSTREAM_INVITE.to_string();
        let last = s.pop().unwrap();
        s.push(if last == 'm' { 'q' } else { 'm' });
        let err = check_invite(&s).unwrap_err().to_string();
        assert!(err.contains("checksum"), "{err}");
    }

    #[test]
    fn other_codes_are_refused() {
        for bad in [
            "",
            "lnbc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "fed11qqqqqqqq",
            "Fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pm",
            "fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pb",
        ] {
            assert!(check_invite(bad).is_err(), "{bad:?} passed");
        }
    }

    #[test]
    fn the_object_is_canonical_and_sets_the_three_fields() {
        let out = successor_meta(None, &notice(), NOW).unwrap();
        assert_eq!(
            out,
            format!(
                r#"{{"federation_expiry_timestamp":"1795000000","federation_successor":"{UPSTREAM_INVITE}","welcome_message":"Moved to the successor federation."}}"#
            )
        );
    }

    #[test]
    fn current_keys_are_kept_and_input_order_does_not_change_the_bytes() {
        let a = r#"{"revision":3,"value":{"zeta":{"b":1,"a":[2,{"y":0,"x":1}]},"federation_name":"v1"}}"#;
        let b = r#"{"federation_name": "v1", "zeta": {"a": [2, {"x": 1, "y": 0}], "b": 1}}"#;
        let out_a = successor_meta(Some(a), &notice(), NOW).unwrap();
        let out_b = successor_meta(Some(b), &notice(), NOW).unwrap();
        assert_eq!(out_a, out_b);
        assert!(
            out_a.starts_with(
                r#"{"federation_expiry_timestamp":"1795000000","federation_name":"v1","#
            ),
            "{out_a}"
        );
        assert!(
            out_a.ends_with(r#""zeta":{"a":[2,{"x":1,"y":0}],"b":1}}"#),
            "{out_a}"
        );
    }

    #[test]
    fn a_bare_object_with_a_value_key_is_not_unwrapped() {
        let bare = r#"{"value":"kept","federation_name":"v1"}"#;
        let out = successor_meta(Some(bare), &notice(), NOW).unwrap();
        assert!(
            out.contains(r#""value":"kept""#) && out.contains(r#""federation_name":"v1""#),
            "{out}"
        );
    }

    #[test]
    fn the_printed_command_quotes_an_apostrophe() {
        assert_eq!(shell_quote("it's"), r#"'it'\''s'"#);
        assert_eq!(shell_quote("{}"), "'{}'");
    }

    #[test]
    fn an_earlier_notice_is_replaced() {
        let old = r#"{"federation_successor":"fed1old","welcome_message":"old"}"#;
        let out = successor_meta(Some(old), &notice(), NOW).unwrap();
        assert!(
            !out.contains("fed1old") && !out.contains("\"old\""),
            "{out}"
        );
    }

    #[test]
    fn empty_current_reads_as_none() {
        let none = successor_meta(None, &notice(), NOW).unwrap();
        for empty in ["", "  ", "null", r#"{"revision":0,"value":null}"#, "{}"] {
            assert_eq!(
                successor_meta(Some(empty), &notice(), NOW).unwrap(),
                none,
                "{empty:?}"
            );
        }
    }

    #[test]
    fn bad_inputs_are_refused() {
        let mut n = notice();
        n.expires_at = NOW;
        assert!(
            successor_meta(None, &n, NOW).is_err(),
            "an expiry now passed"
        );
        let mut n = notice();
        n.message = "  ".into();
        assert!(
            successor_meta(None, &n, NOW).is_err(),
            "an empty message passed"
        );
        assert!(
            successor_meta(Some("[1]"), &notice(), NOW).is_err(),
            "an array passed"
        );
        assert!(
            successor_meta(Some("{"), &notice(), NOW).is_err(),
            "broken JSON passed"
        );
    }

    #[test]
    fn expiry_reads_seconds_and_dates() {
        assert_eq!(parse_expiry("1795000000").unwrap(), 1_795_000_000);
        assert_eq!(parse_expiry("1970-01-01").unwrap(), 0);
        assert_eq!(parse_expiry("2026-11-25").unwrap(), 1_795_564_800);
        assert_eq!(parse_expiry("2028-02-29").unwrap(), 1_835_395_200);
        for bad in [
            "1969-12-31",
            "2026-11-00",
            "2027-02-29",
            "2026-13-01",
            "2026-1-01",
            "26-11-25",
            "soon",
            "",
            "-5",
        ] {
            assert!(parse_expiry(bad).is_err(), "{bad:?} passed");
        }
    }
}
