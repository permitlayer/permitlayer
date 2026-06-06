//! Shape a Gmail `messages.get`/`threads.get` response into a compact,
//! agent-friendly JSON object: prioritized text body + an attachment
//! manifest, with attachment byte payloads stripped.
//!
//! # Why
//!
//! `format=full` returns the full MIME tree in `payload`. Genuine
//! attachments come back as `body.attachmentId` with empty `body.data`
//! (Gmail sends them out-of-band by MIME structure, verified against the
//! API docs), so a single large PDF does NOT inline. The residual
//! blow-up risk is many small *inline* parts that DO carry `body.data`
//! (e.g. embedded images) or an oversized HTML body. This shaper:
//!
//! - extracts the message body, prioritizing `text/plain` (capped at
//!   [`MAX_BODY_BYTES`]) then `text/html` (capped harder at
//!   [`MAX_HTML_BODY_BYTES`]);
//! - emits one manifest entry per attachment part, stripping inline
//!   `data` UNLESS the part has no `attachmentId` AND its base64 is small
//!   (≤ [`MAX_INLINE_DATA_BYTES`]); a large inline blob is dropped (it's
//!   unfetchable, so the entry is flagged `inline_dropped`);
//! - never reconstructs a field from a pre-scrub source — it operates on
//!   the already-scrubbed body JSON the proxy hands it (so the scrub
//!   engine's redactions survive into the shaped output).
//!
//! Pure functions, no I/O. The `part_lookup` helper is reused by the
//! attachment-fetch handler to resolve a part's `filename`/`mimeType`.

use serde::Serialize;
use serde_json::Value;

/// Maximum decoded text/plain body size embedded in a shaped response
/// (32 KiB, ≈8K tokens). Larger bodies are truncated with `truncated =
/// true`; an agent that needs the full body can request `format=raw`.
/// Lowered from 64 KiB after a Gmail-summary cron fed multiple ~60 KB
/// bodies into one turn and drove model context to ~51K tokens.
pub const MAX_BODY_BYTES: usize = 32 * 1024;

/// Maximum size for an HTML-derived body (16 KiB). HTML is token-dense and
/// low-signal (markup/CSS/tracking), so it's capped harder than plain text;
/// `html_available = true` already tells the agent richer content exists.
pub const MAX_HTML_BODY_BYTES: usize = 16 * 1024;

/// Maximum base64 length of an inline part's `data` to retain inline
/// (8 KiB of base64 ≈ 6 KB decoded). Inline parts have no `attachmentId`,
/// so their bytes can't be re-fetched — but a newsletter's inline base64
/// image can be tens of KB and is the dominant payload-bloat source. Larger
/// inline blobs are dropped (manifest entry kept, `inline_dropped = true`).
pub const MAX_INLINE_DATA_BYTES: usize = 8 * 1024;

/// A shaped, agent-friendly message.
#[derive(Debug, Serialize, PartialEq)]
pub struct ShapedMessage {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub label_ids: Vec<String>,
    pub body: ShapedBody,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<ShapedAttachment>,
}

/// The extracted message body.
#[derive(Debug, Serialize, PartialEq, Default)]
pub struct ShapedBody {
    /// Decoded body text (text/plain preferred, else text/html), capped.
    pub text: String,
    /// Whether a `text/html` alternative exists (whether or not `text` came
    /// from it).
    pub html_available: bool,
    /// Whether `text` was truncated at [`MAX_BODY_BYTES`].
    pub truncated: bool,
}

/// One attachment manifest entry.
#[derive(Debug, Serialize, PartialEq)]
pub struct ShapedAttachment {
    /// Stable per-message handle (`att-0`, `att-1`, …).
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Gmail's attachment ID — pass to `gmail.attachments.get` to fetch the
    /// bytes. Absent for small inline parts that carried their data inline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_id: Option<String>,
    /// Kept ONLY for inline parts that had `data`, no `attachmentId`, AND
    /// base64 length ≤ [`MAX_INLINE_DATA_BYTES`] (otherwise unfetchable but
    /// small enough to inline). base64url.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_data: Option<String>,
    /// True when a large inline part's bytes were dropped: it had `data` but
    /// no `attachmentId` (so it's unfetchable) and exceeded
    /// [`MAX_INLINE_DATA_BYTES`]. Distinguishes "no bytes because
    /// re-fetchable" from "no bytes because too large and lost". Omitted
    /// (false) in the common case.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub inline_dropped: bool,
}

/// Shape one Gmail message JSON (the body of `messages.get?format=full`,
/// already scrubbed) into a [`ShapedMessage`]. Returns `None` if the JSON
/// has no `id` (not a message object).
pub fn shape_message(msg: &Value) -> Option<ShapedMessage> {
    let id = msg.get("id")?.as_str()?.to_owned();
    let thread_id = str_field(msg, "threadId");
    let snippet = str_field(msg, "snippet");
    let label_ids = msg
        .get("labelIds")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();

    let payload = msg.get("payload");
    let headers = payload.map(collect_headers).unwrap_or_default();

    let mut body = ShapedBody::default();
    let mut html_text: Option<String> = None;
    let mut attachments = Vec::new();
    let mut counter = 0usize;
    if let Some(p) = payload {
        walk_part(p, &mut body, &mut html_text, &mut attachments, &mut counter);
    }
    // Prefer text/plain (already in body.text if found); else fall back to
    // the captured text/html.
    if body.text.is_empty()
        && let Some(html) = html_text
    {
        body.text = cap_body(&html, MAX_HTML_BODY_BYTES, &mut body.truncated);
    }

    Some(ShapedMessage {
        id,
        thread_id,
        from: header(&headers, "from"),
        to: header(&headers, "to"),
        cc: header(&headers, "cc"),
        subject: header(&headers, "subject"),
        date: header(&headers, "date"),
        snippet,
        label_ids,
        body,
        attachments,
    })
}

/// Shape a Gmail thread JSON (`threads.get`) into per-message shaped
/// objects.
pub fn shape_thread(thread: &Value) -> Vec<ShapedMessage> {
    thread
        .get("messages")
        .and_then(|v| v.as_array())
        .map(|msgs| msgs.iter().filter_map(shape_message).collect())
        .unwrap_or_default()
}

/// Find the `filename` + `mimeType` of the part in `msg` whose
/// `body.attachmentId` equals `attachment_id`. Reused by the
/// attachment-fetch handler (Gmail's `attachments.get` returns neither).
/// Returns `(filename, mime_type)`.
pub fn part_lookup(msg: &Value, attachment_id: &str) -> Option<(Option<String>, Option<String>)> {
    fn search(part: &Value, target: &str) -> Option<(Option<String>, Option<String>)> {
        if part.get("body").and_then(|b| b.get("attachmentId")).and_then(|v| v.as_str())
            == Some(target)
        {
            let filename = str_field(part, "filename").filter(|s| !s.is_empty());
            let mime = str_field(part, "mimeType");
            return Some((filename, mime));
        }
        if let Some(parts) = part.get("parts").and_then(|v| v.as_array()) {
            for child in parts {
                if let Some(found) = search(child, target) {
                    return Some(found);
                }
            }
        }
        None
    }
    msg.get("payload").and_then(|p| search(p, attachment_id))
}

// ── internals ──────────────────────────────────────────────────────────

/// Recursively walk a MIME part, filling the body (text/plain → `body`,
/// text/html → `html_text`) and the attachment manifest.
fn walk_part(
    part: &Value,
    body: &mut ShapedBody,
    html_text: &mut Option<String>,
    attachments: &mut Vec<ShapedAttachment>,
    counter: &mut usize,
) {
    let mime = part.get("mimeType").and_then(|v| v.as_str()).unwrap_or("");
    let filename = part.get("filename").and_then(|v| v.as_str()).unwrap_or("");
    let part_body = part.get("body");
    let data = part_body.and_then(|b| b.get("data")).and_then(|v| v.as_str());
    let attachment_id = part_body.and_then(|b| b.get("attachmentId")).and_then(|v| v.as_str());
    let size = part_body.and_then(|b| b.get("size")).and_then(serde_json::Value::as_u64);

    let is_attachment = !filename.is_empty()
        || is_attachment_disposition(part)
        || (!mime.starts_with("text/") && !mime.starts_with("multipart/"));

    if is_attachment {
        *counter += 1;
        let id = format!("att-{}", *counter - 1);
        // Strip bytes when re-fetchable (has attachmentId). For inline parts
        // (no attachmentId, otherwise unfetchable) keep the bytes only when
        // small — a large inline base64 blob (e.g. a newsletter image) is
        // the dominant payload-bloat source, so drop it and flag it.
        let (inline_data, inline_dropped) = match (attachment_id, data) {
            (None, Some(d)) if d.len() <= MAX_INLINE_DATA_BYTES => (Some(d.to_owned()), false),
            (None, Some(_)) => (None, true),
            _ => (None, false),
        };
        attachments.push(ShapedAttachment {
            id,
            filename: (!filename.is_empty()).then(|| filename.to_owned()),
            mime_type: (!mime.is_empty()).then(|| mime.to_owned()),
            size,
            attachment_id: attachment_id.map(str::to_owned),
            inline_data,
            inline_dropped,
        });
        return;
    }

    // Text bodies.
    if mime == "text/plain" {
        if let Some(d) = data
            && body.text.is_empty()
            && let Some(decoded) = decode_body(d)
        {
            body.text = cap_body(&decoded, MAX_BODY_BYTES, &mut body.truncated);
        }
    } else if mime == "text/html" {
        body.html_available = true;
        if html_text.is_none()
            && let Some(d) = data
            && let Some(decoded) = decode_body(d)
        {
            *html_text = Some(decoded);
        }
    }

    // Recurse into container parts.
    if let Some(parts) = part.get("parts").and_then(|v| v.as_array()) {
        for child in parts {
            walk_part(child, body, html_text, attachments, counter);
        }
    }
}

/// Whether a part's headers declare `Content-Disposition: attachment`.
fn is_attachment_disposition(part: &Value) -> bool {
    part.get("headers")
        .and_then(|v| v.as_array())
        .map(|hs| {
            hs.iter().any(|h| {
                h.get("name")
                    .and_then(|v| v.as_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("content-disposition"))
                    && h.get("value")
                        .and_then(|v| v.as_str())
                        .is_some_and(|v| v.to_ascii_lowercase().contains("attachment"))
            })
        })
        .unwrap_or(false)
}

/// Decode a base64url body part (`body.data`). Gmail uses URL-safe base64,
/// no padding. Returns the UTF-8 text, or `None` if it doesn't decode.
fn decode_body(data: &str) -> Option<String> {
    let bytes = permitlayer_core::files::decode_base64url_maybe_padded(data)?;
    String::from_utf8(bytes).ok()
}

/// Truncate text to `limit` bytes at a char boundary, setting `truncated`
/// if it had to cut. Callers pass [`MAX_BODY_BYTES`] for plain text and the
/// smaller [`MAX_HTML_BODY_BYTES`] for HTML-derived bodies.
fn cap_body(text: &str, limit: usize, truncated: &mut bool) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    *truncated = true;
    let end = (0..=limit).rev().find(|&i| text.is_char_boundary(i)).unwrap_or(0);
    text[..end].to_owned()
}

type Headers = Vec<(String, String)>;

/// Collect `payload.headers` into lowercased-name → value pairs.
fn collect_headers(payload: &Value) -> Headers {
    payload
        .get("headers")
        .and_then(|v| v.as_array())
        .map(|hs| {
            hs.iter()
                .filter_map(|h| {
                    let name = h.get("name")?.as_str()?.to_ascii_lowercase();
                    let value = h.get("value")?.as_str()?.to_owned();
                    Some((name, value))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn header(headers: &Headers, name: &str) -> Option<String> {
    headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use permitlayer_core::agent::base64_url_no_pad_encode;
    use serde_json::json;

    fn b64(s: &str) -> String {
        base64_url_no_pad_encode(s.as_bytes())
    }

    #[test]
    fn shapes_multipart_alternative_body_and_strips_attachment() {
        let msg = json!({
            "id": "m1",
            "threadId": "t1",
            "snippet": "hello there",
            "labelIds": ["INBOX"],
            "payload": {
                "headers": [
                    {"name": "From", "value": "a@example.com"},
                    {"name": "Subject", "value": "Hi"}
                ],
                "mimeType": "multipart/mixed",
                "parts": [
                    {
                        "mimeType": "multipart/alternative",
                        "parts": [
                            {"mimeType": "text/plain", "body": {"data": b64("plain body")}},
                            {"mimeType": "text/html", "body": {"data": b64("<p>html body</p>")}}
                        ]
                    },
                    {
                        "mimeType": "application/pdf",
                        "filename": "invoice.pdf",
                        "body": {"attachmentId": "ANGabc", "size": 412889}
                    }
                ]
            }
        });
        let shaped = shape_message(&msg).unwrap();
        assert_eq!(shaped.id, "m1");
        assert_eq!(shaped.from.as_deref(), Some("a@example.com"));
        assert_eq!(shaped.subject.as_deref(), Some("Hi"));
        assert_eq!(shaped.body.text, "plain body"); // text/plain prioritized
        assert!(shaped.body.html_available);
        assert!(!shaped.body.truncated);
        assert_eq!(shaped.attachments.len(), 1);
        let att = &shaped.attachments[0];
        assert_eq!(att.filename.as_deref(), Some("invoice.pdf"));
        assert_eq!(att.mime_type.as_deref(), Some("application/pdf"));
        assert_eq!(att.attachment_id.as_deref(), Some("ANGabc"));
        assert_eq!(att.size, Some(412889));
        // No bytes anywhere in the shaped output.
        assert!(att.inline_data.is_none());
        let serialized = serde_json::to_string(&shaped).unwrap();
        assert!(!serialized.contains("ANGabc") || !serialized.contains("data"));
        assert!(!serialized.contains(&b64("plain body")[..]));
    }

    #[test]
    fn html_only_falls_back_to_html() {
        let msg = json!({
            "id": "m2",
            "payload": {
                "mimeType": "text/html",
                "body": {"data": b64("<p>only html</p>")}
            }
        });
        let shaped = shape_message(&msg).unwrap();
        assert_eq!(shaped.body.text, "<p>only html</p>");
        assert!(shaped.body.html_available);
    }

    #[test]
    fn inline_attachment_without_attachmentid_keeps_bytes() {
        // Small inline image with data but no attachmentId — must NOT be
        // discarded (it's otherwise unfetchable).
        let data = b64("PNGDATA");
        let msg = json!({
            "id": "m3",
            "payload": {
                "mimeType": "multipart/mixed",
                "parts": [
                    {"mimeType": "text/plain", "body": {"data": b64("body")}},
                    {"mimeType": "image/png", "filename": "logo.png",
                     "body": {"data": data, "size": 7}}
                ]
            }
        });
        let shaped = shape_message(&msg).unwrap();
        assert_eq!(shaped.attachments.len(), 1);
        let att = &shaped.attachments[0];
        assert!(att.attachment_id.is_none());
        assert_eq!(att.inline_data.as_deref(), Some(b64("PNGDATA").as_str()));
        assert!(!att.inline_dropped, "small inline part is kept, not dropped");
    }

    #[test]
    fn large_inline_data_is_dropped() {
        // Inline part, no attachmentId, base64 length > MAX_INLINE_DATA_BYTES
        // (a newsletter's inline image) — bytes dropped, flagged.
        let big = b64(&"P".repeat(MAX_INLINE_DATA_BYTES + 1024));
        assert!(big.len() > MAX_INLINE_DATA_BYTES);
        let msg = json!({
            "id": "m5",
            "payload": {
                "mimeType": "multipart/mixed",
                "parts": [
                    {"mimeType": "text/plain", "body": {"data": b64("body")}},
                    {"mimeType": "image/png", "filename": "huge.png",
                     "body": {"data": big, "size": 99999}}
                ]
            }
        });
        let shaped = shape_message(&msg).unwrap();
        let att = &shaped.attachments[0];
        assert!(att.attachment_id.is_none());
        assert!(att.inline_data.is_none(), "large inline bytes must be dropped");
        assert!(att.inline_dropped, "drop must be flagged");
    }

    #[test]
    fn inline_data_at_threshold_is_kept() {
        // base64 length right at the limit is kept (boundary is `<=`).
        let payload = "Q".repeat(MAX_INLINE_DATA_BYTES);
        let msg = json!({
            "id": "m6",
            "payload": {
                "mimeType": "multipart/mixed",
                "parts": [
                    {"mimeType": "image/png", "filename": "ok.png",
                     "body": {"data": payload, "size": 10}}
                ]
            }
        });
        let shaped = shape_message(&msg).unwrap();
        let att = &shaped.attachments[0];
        assert!(att.inline_data.is_some(), "at-threshold inline bytes are kept");
        assert!(!att.inline_dropped);
    }

    #[test]
    fn body_truncates_at_cap() {
        let big = "x".repeat(MAX_BODY_BYTES + 100);
        let msg = json!({
            "id": "m4",
            "payload": {"mimeType": "text/plain", "body": {"data": b64(&big)}}
        });
        let shaped = shape_message(&msg).unwrap();
        assert!(shaped.body.truncated);
        assert!(shaped.body.text.len() <= MAX_BODY_BYTES);
    }

    #[test]
    fn html_fallback_capped_at_smaller_limit() {
        // An HTML-only body between the HTML cap and the (larger) plain cap
        // must be truncated at the HTML limit, not the plain one.
        let big_html = "h".repeat(MAX_BODY_BYTES);
        assert!(big_html.len() > MAX_HTML_BODY_BYTES);
        let msg = json!({
            "id": "m7",
            "payload": {"mimeType": "text/html", "body": {"data": b64(&big_html)}}
        });
        let shaped = shape_message(&msg).unwrap();
        assert!(shaped.body.truncated);
        assert!(
            shaped.body.text.len() <= MAX_HTML_BODY_BYTES,
            "HTML body must be capped at the smaller HTML limit"
        );
    }

    #[test]
    fn inline_dropped_omitted_from_json_when_false() {
        // skip_serializing_if keeps the common case byte-free.
        let msg = json!({
            "id": "m8",
            "payload": {
                "mimeType": "multipart/mixed",
                "parts": [
                    {"mimeType": "application/pdf", "filename": "doc.pdf",
                     "body": {"attachmentId": "att-xyz", "size": 1000}}
                ]
            }
        });
        let shaped = shape_message(&msg).unwrap();
        let s = serde_json::to_string(&shaped).unwrap();
        assert!(!s.contains("inline_dropped"), "inline_dropped omitted when false: {s}");
    }

    #[test]
    fn thread_shapes_each_message() {
        let thread = json!({
            "messages": [
                {"id": "m1", "payload": {"mimeType": "text/plain", "body": {"data": b64("one")}}},
                {"id": "m2", "payload": {"mimeType": "text/plain", "body": {"data": b64("two")}}}
            ]
        });
        let shaped = shape_thread(&thread);
        assert_eq!(shaped.len(), 2);
        assert_eq!(shaped[0].body.text, "one");
        assert_eq!(shaped[1].body.text, "two");
    }

    #[test]
    fn part_lookup_finds_nested_attachment() {
        let msg = json!({
            "payload": {
                "parts": [
                    {"mimeType": "text/plain", "body": {"data": "x"}},
                    {"mimeType": "application/pdf", "filename": "r.pdf",
                     "body": {"attachmentId": "ATT9"}}
                ]
            }
        });
        let (filename, mime) = part_lookup(&msg, "ATT9").unwrap();
        assert_eq!(filename.as_deref(), Some("r.pdf"));
        assert_eq!(mime.as_deref(), Some("application/pdf"));
        assert!(part_lookup(&msg, "nope").is_none());
    }
}
