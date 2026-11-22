//! Crypto primitives:
//! - password hashes: scrypt (N=16384, r=16, p=1, dkLen=64), `hex(salt):hex(key)`
//! - signed cookies: `value.base64(HMAC-SHA256(secret, value))`
//! - email tokens: HS256 JWTs

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;

type HmacSha256 = Hmac<Sha256>;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Uniformly random string over `alphabet` (rejection sampling, no modulo bias).
pub fn random_string_from(len: usize, alphabet: &[u8]) -> String {
    assert!(!alphabet.is_empty() && alphabet.len() <= 256);
    let limit = 256 - (256 % alphabet.len());
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for b in random_bytes::<64>() {
            if (b as usize) < limit {
                out.push(alphabet[b as usize % alphabet.len()] as char);
                if out.len() == len {
                    break;
                }
            }
        }
    }
    out
}

pub fn random_string(len: usize) -> String {
    random_string_from(len, ALPHANUMERIC)
}

/// Default id generator: 32 alphanumeric characters.
pub fn generate_id() -> String {
    random_string(32)
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

pub fn sign_value(secret: &str, value: &str) -> String {
    let sig = STANDARD.encode(hmac_sha256(secret.as_bytes(), value.as_bytes()));
    format!("{value}.{sig}")
}

/// Verify a `value.signature` string; returns `value` when the signature is valid.
pub fn verify_signed_value(secret: &str, signed: &str) -> Option<String> {
    let (value, sig) = signed.rsplit_once('.')?;
    if sig.len() != 44 || !sig.ends_with('=') {
        return None;
    }
    let given = STANDARD.decode(sig).ok()?;
    let expected = hmac_sha256(secret.as_bytes(), value.as_bytes());
    constant_time_eq(&given, &expected).then(|| value.to_string())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn base64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// PKCE S256 code challenge.
pub fn pkce_challenge(verifier: &str) -> String {
    base64url(&sha256(verifier.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Password hashing strategy. Hashing is CPU bound; ferroauth calls it on a
/// blocking thread.
pub trait PasswordHasher: Send + Sync + 'static {
    fn hash(&self, password: &str) -> String;
    fn verify(&self, hash: &str, password: &str) -> bool;
}

/// Default password hasher: scrypt, NFKC-normalised password, stored as `hex(salt):hex(key)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScryptHasher;

impl ScryptHasher {
    fn derive(password: &str, salt_hex: &str) -> [u8; 64] {
        // log2(16384) = 14, r = 16, p = 1, dkLen = 64
        let params = scrypt::Params::new(14, 16, 1, 64).expect("valid scrypt params");
        let normalized: String = password.nfkc().collect();
        let mut out = [0u8; 64];
        // The salt's hex string (not its raw bytes) is the scrypt salt.
        scrypt::scrypt(normalized.as_bytes(), salt_hex.as_bytes(), &params, &mut out).expect("valid output length");
        out
    }
}

impl PasswordHasher for ScryptHasher {
    fn hash(&self, password: &str) -> String {
        let salt = hex(&random_bytes::<16>());
        let key = Self::derive(password, &salt);
        format!("{salt}:{}", hex(&key))
    }

    fn verify(&self, hash: &str, password: &str) -> bool {
        let Some((salt, key_hex)) = hash.split_once(':') else { return false };
        let Some(expected) = unhex(key_hex) else { return false };
        constant_time_eq(&Self::derive(password, salt), &expected)
    }
}

/// Minimal HS256 JWT (header `{"alg":"HS256"}`), used for email verification tokens.
pub fn sign_jwt(secret: &str, mut claims: serde_json::Map<String, Value>, expires_in_secs: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    claims.insert("iat".into(), now.into());
    claims.insert("exp".into(), (now + expires_in_secs).into());
    let header = base64url(br#"{"alg":"HS256"}"#);
    let payload = base64url(Value::Object(claims).to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = base64url(&hmac_sha256(secret.as_bytes(), signing_input.as_bytes()));
    format!("{signing_input}.{sig}")
}

#[derive(Debug, PartialEq, Eq)]
pub enum JwtError {
    Invalid,
    Expired,
}

pub fn verify_jwt(secret: &str, token: &str) -> Result<serde_json::Map<String, Value>, JwtError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(JwtError::Invalid);
    };
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).map_err(|_| JwtError::Invalid)?).map_err(|_| JwtError::Invalid)?;
    if header.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Err(JwtError::Invalid);
    }
    let sig = URL_SAFE_NO_PAD.decode(s).map_err(|_| JwtError::Invalid)?;
    let expected = hmac_sha256(secret.as_bytes(), format!("{h}.{p}").as_bytes());
    if !constant_time_eq(&sig, &expected) {
        return Err(JwtError::Invalid);
    }
    let claims: serde_json::Map<String, Value> =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).map_err(|_| JwtError::Invalid)?).map_err(|_| JwtError::Invalid)?;
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
        if exp < chrono::Utc::now().timestamp() {
            return Err(JwtError::Expired);
        }
    }
    Ok(claims)
}

// ---- random string alphabets ------------------------------------------------------------

/// `a-z 0-9 A-Z - _`.
pub const URL_SAFE_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
pub const DIGITS: &[u8] = b"0123456789";

/// `base64url(HMAC-SHA256(secret, msg))` without padding.
pub fn hmac_base64url(secret: &str, msg: &str) -> String {
    base64url(&hmac_sha256(secret.as_bytes(), msg.as_bytes()))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex(bytes)
}

// ---- symmetric encryption ----------------------------------------------------------------

/// XChaCha20-Poly1305 with key `SHA-256(secret)`; output `hex(nonce || ciphertext || tag)`.
pub fn symmetric_encrypt(secret: &str, data: &str) -> String {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let cipher = XChaCha20Poly1305::new(&sha256(secret.as_bytes()).into());
    let nonce = random_bytes::<24>();
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), data.as_bytes()).expect("encryption cannot fail");
    let mut out = nonce.to_vec();
    out.extend(ct);
    hex(&out)
}

/// Inverse of [`symmetric_encrypt`].
pub fn symmetric_decrypt(secret: &str, data: &str) -> Option<String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let bytes = unhex(data)?;
    if bytes.len() < 24 + 16 {
        return None;
    }
    let (nonce, ct) = bytes.split_at(24);
    let cipher = XChaCha20Poly1305::new(&sha256(secret.as_bytes()).into());
    String::from_utf8(cipher.decrypt(XNonce::from_slice(nonce), ct).ok()?).ok()
}

// ---- one-time passwords (RFC 4226 / 6238) ------------------------------------------------

pub fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let r = mac.finalize().into_bytes();
    let o = (r[r.len() - 1] & 0x0f) as usize;
    let bin = ((r[o] as u32 & 0x7f) << 24) | ((r[o + 1] as u32) << 16) | ((r[o + 2] as u32) << 8) | r[o + 3] as u32;
    format!("{:0width$}", bin % 10u32.pow(digits), width = digits as usize)
}

pub fn totp_at(key: &[u8], unix_secs: i64, period: u64, digits: u32) -> String {
    hotp(key, (unix_secs.max(0) as u64) / period, digits)
}

pub fn totp_now(key: &[u8], period: u64, digits: u32) -> String {
    totp_at(key, chrono::Utc::now().timestamp(), period, digits)
}

/// Accepts the current code and `window` steps either side; constant time per candidate.
pub fn verify_totp(key: &[u8], code: &str, period: u64, digits: u32, window: i64) -> bool {
    let counter = (chrono::Utc::now().timestamp().max(0) as u64 / period) as i64;
    let mut matched = false;
    for i in -window..=window {
        let c = counter + i;
        if c >= 0 {
            matched |= constant_time_eq(code.as_bytes(), hotp(key, c as u64, digits).as_bytes());
        }
    }
    matched
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, no padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(BASE32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = BASE32.iter().position(|&x| x == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// `otpauth://totp/...` provisioning URI (what authenticator apps scan).
pub fn otpauth_url(issuer: &str, account: &str, secret: &[u8], digits: u32, period: u64) -> String {
    use crate::cookies::encode_uri_component as enc;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", &base32_encode(secret))
        .append_pair("issuer", issuer)
        .append_pair("digits", &digits.to_string())
        .append_pair("period", &period.to_string())
        .finish();
    format!("otpauth://totp/{}:{}?{query}", enc(issuer), enc(account))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrypt_roundtrip() {
        let h = ScryptHasher.hash("hunter2 password");
        assert!(ScryptHasher.verify(&h, "hunter2 password"));
        assert!(!ScryptHasher.verify(&h, "wrong"));
        assert!(!ScryptHasher.verify("garbage", "wrong"));
    }

    /// Known-answer vectors for the password hash and cookie signature formats.
    #[test]
    fn known_answer_vectors() {
        let stored_hash = "d3e7c26a1c99494a795e01f67a4269e3:86993bb1e3c7e76f2863fbba21a36cb1423a6c12ec687dd643389bb0e838061888b9225cb4cbf9124bf6956afe2cd79da798979bc883412bd75bd93f3b9ffda2";
        assert!(ScryptHasher.verify(stored_hash, "correct horse battery staple"));
        assert!(!ScryptHasher.verify(stored_hash, "correct horse battery stapler"));

        let signed = sign_value("test-secret-test-secret-test-secret-0123", "session-token-abc");
        assert_eq!(
            crate::cookies::encode_uri_component(&signed),
            "session-token-abc.QzPpC2hgduvyF%2B4%2Bg3fwkI7FnxWu%2FfZvA7qVvjvVu4Q%3D"
        );
    }

    /// Known-answer vectors for encryption, HOTP and provisioning URIs.
    #[test]
    fn two_factor_known_answer_vectors() {
        let key = "test-secret-test-secret-test-secret-0123";
        let secret = "aB3-xY_9kLmN0pQrStUvWxYz12345678";
        let enc = "a739f8a8790b5012ecfd01062f32d45ba02bacc9d06619ddefef77476ad3f8ba8be9014d660cdf4b0cc045b55d263df332796300e0dcc88abfe6c45331dcfa76a7c1f79a5fe41cdb";
        assert_eq!(symmetric_decrypt(key, enc).as_deref(), Some(secret));
        let codes = "edb04449a63360eb667efb128ef23b40af0b54fc1e92232e22fbb05cfe5d379a1c54a02fa0276ad2417342644eb5dca7643b76a70787a3530a53d4c54690d2bb7f65d7122e";
        assert_eq!(symmetric_decrypt(key, codes).as_deref(), Some(r#"["abcde-12345","ZZZZZ-00000"]"#));
        assert_eq!(hotp(secret.as_bytes(), 0, 6), "186740");
        assert_eq!(hotp(secret.as_bytes(), 12345, 6), "789563");
        assert_eq!(
            otpauth_url("My App & Co", "ada@example.com", secret.as_bytes(), 6, 30),
            "otpauth://totp/My%20App%20%26%20Co:ada%40example.com?secret=MFBDGLLYLFPTS22MNVHDA4CROJJXIVLWK54FS6RRGIZTINJWG44A&issuer=My+App+%26+Co&digits=6&period=30"
        );
    }

    /// RFC 6238 appendix B (SHA-1).
    #[test]
    fn totp_rfc_vectors() {
        let key = b"12345678901234567890";
        assert_eq!(totp_at(key, 59, 30, 8), "94287082");
        assert_eq!(totp_at(key, 1111111109, 30, 8), "07081804");
        assert_eq!(totp_at(key, 20000000000, 30, 8), "65353130");
        assert!(verify_totp(key, &totp_now(key, 30, 6), 30, 6, 1));
        assert!(!verify_totp(key, "000000x", 30, 6, 1));
    }

    #[test]
    fn base32_roundtrip() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(base32_decode("mzxw6ytboi======").unwrap(), b"foobar");
    }

    #[test]
    fn symmetric_roundtrip() {
        let enc = symmetric_encrypt("k", "hello");
        assert_eq!(symmetric_decrypt("k", &enc).as_deref(), Some("hello"));
        assert_eq!(symmetric_decrypt("other", &enc), None);
    }

    #[test]
    fn signed_values() {
        let s = sign_value("secret", "abc");
        assert_eq!(verify_signed_value("secret", &s).as_deref(), Some("abc"));
        assert_eq!(verify_signed_value("other", &s), None);
        assert_eq!(verify_signed_value("secret", "abc.nope"), None);
    }

    #[test]
    fn jwt_roundtrip() {
        let mut c = serde_json::Map::new();
        c.insert("email".into(), "a@b.c".into());
        let t = sign_jwt("s", c, 60);
        assert_eq!(verify_jwt("s", &t).unwrap()["email"], "a@b.c");
        assert_eq!(verify_jwt("x", &t), Err(JwtError::Invalid));
        let expired = sign_jwt("s", serde_json::Map::new(), -10);
        assert_eq!(verify_jwt("s", &expired), Err(JwtError::Expired));
    }

    #[test]
    fn random_ids() {
        let id = generate_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(id, generate_id());
    }
}
