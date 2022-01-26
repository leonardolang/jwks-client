use std::time::{Duration, SystemTime};

use base64::{decode_config, Config, STANDARD_NO_PAD};
use regex::Regex;
use reqwest;
use reqwest::Response;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_512_8192_SHA256_FOR_LEGACY_USE_ONLY};
use serde::{
    de::DeserializeOwned,
    {Deserialize, Serialize},
};
use serde_json::Value;
use log::{info, debug};

use crate::error::*;
use crate::jwt::*;


type HeaderBody = String;
pub type Signature = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtKey {
    #[serde(default)] // https://github.com/jfbilodeau/jwks-client/issues/1
    pub e: String,
    pub kty: String,
    #[serde(default = "default_alg")]
    pub alg: String,
    #[serde(default)] // https://github.com/jfbilodeau/jwks-client/issues/1
    pub n: String,
    pub kid: String,
}

fn default_alg() -> String {
    "".to_string()
}

fn normalize_and_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError>
{
    let data_std64 = data.replace("-", "+").replace("_", "/");
    let data_bytes = &mut data_std64.as_bytes().to_vec();
    let leftover = data_bytes.len() % 4;
    let pad = if leftover != 0 { 4 - leftover } else { 0 };
    for _ in 0..pad { data_bytes.push(b'='); };
    debug!("=> {}", String::from_utf8_lossy(data_bytes));
    let forgiving_urlsafe_nopad = Config::decode_allow_trailing_bits(STANDARD_NO_PAD, true);
    decode_config(&data_bytes, forgiving_urlsafe_nopad)
}

impl JwtKey {
    pub fn new(kid: &str, n: &str, e: &str) -> JwtKey {
        JwtKey {
            e: e.to_owned(),
            kty: "JTW".to_string(),
            alg: "RS256".to_string(),
            n: n.to_owned(),
            kid: kid.to_owned(),
        }
    }
}

impl Clone for JwtKey {
    fn clone(&self) -> Self {
        JwtKey {
            e: self.e.clone(),
            kty: self.kty.clone(),
            alg: self.alg.clone(),
            n: self.n.clone(),
            kid: self.kid.clone(),
        }
    }
}

pub struct KeyStore {
    key_url: String,
    keys: Vec<JwtKey>,
    refresh_interval: f64,
    load_time: Option<SystemTime>,
    expire_time: Option<SystemTime>,
    refresh_time: Option<SystemTime>,
}

impl KeyStore {
    pub fn new() -> KeyStore {
        let key_store = KeyStore {
            key_url: "".to_owned(),
            keys: vec![],
            refresh_interval: 0.5,
            load_time: None,
            expire_time: None,
            refresh_time: None,
        };

        key_store
    }

    pub async fn new_from(jkws_url: String) -> Result<KeyStore, Error> {
        let mut key_store = KeyStore::new();

        key_store.key_url = jkws_url;

        key_store.load_keys().await?;

        Ok(key_store)
    }

    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    pub fn key_set_url(&self) -> &str {
        &self.key_url
    }

    pub async fn load_keys_from(&mut self, url: String) -> Result<(), Error> {
        self.key_url = url;

        self.load_keys().await?;

        Ok(())
    }

    pub async fn load_keys(&mut self) -> Result<(), Error> {
        #[derive(Deserialize)]
        pub struct JwtKeys {
            pub keys: Vec<JwtKey>,
        }

        let mut response = reqwest::get(&self.key_url).await.map_err(|e| err::get(format!("Could not download JWKS: {:?}", e)))?;

        let load_time = SystemTime::now();
        self.load_time = Some(load_time);

        let result = KeyStore::cache_max_age(&mut response);

        if let Ok(value) = result {
            let expire = load_time + Duration::new(value, 0);
            self.expire_time = Some(expire);
            let refresh_time = (value as f64 * self.refresh_interval) as u64;
            let refresh = load_time + Duration::new(refresh_time, 0);
            self.refresh_time = Some(refresh);
        }

        let jwks = response.json::<JwtKeys>().await.map_err(|e| err::internal(format!("Failed to parse keys {:?}", e)))?;

        jwks.keys.iter().for_each(|k| self.add_key(k));

        Ok(())
    }

    fn cache_max_age(response: &mut Response) -> Result<u64, ()> {
        let header = response.headers().get("cache-control").ok_or(())?;

        let header_text = header.to_str().map_err(|_| ())?;

        let re = Regex::new("max-age\\s*=\\s*(\\d+)").map_err(|_| ())?;

        let captures = re.captures(header_text).ok_or(())?;

        let capture = captures.get(1).ok_or(())?;

        let text = capture.as_str();

        let value = text.parse::<u64>().map_err(|_| ())?;

        Ok(value)
    }

    /// Fetch a key by key id (KID)
    pub fn key_by_id(&self, kid: &str) -> Option<&JwtKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Number of keys in keystore
    pub fn keys_len(&self) -> usize {
        self.keys.len()
    }

    /// Manually add a key to the keystore
    pub fn add_key(&mut self, key: &JwtKey) {
        self.keys.push(key.clone());
    }

    fn decode_segments(&self, token: &str) -> Result<(Header, Payload, Signature, HeaderBody), Error> {
        let raw_segments: Vec<&str> = token.split(".").collect();
        if raw_segments.len() != 3 {
            return Err(err::invalid(format!("JWT does not have 3 segments (total = {:?})", raw_segments.len())));
        }

        let header_segment = raw_segments[0];
        let payload_segment = raw_segments[1];
        let signature_segment = raw_segments[2].to_string();

        let header = Header::new(decode_segment::<Value>(header_segment).or_else(|e| Err(err::header(format!("Failed to decode header: {:?}", e))))?);
        let payload = Payload::new(decode_segment::<Value>(payload_segment).or_else(|e| Err(err::payload(format!("Failed to decode payload: {:?}", e))))?);

        let body = format!("{}.{}", header_segment, payload_segment);

        Ok((header, payload, signature_segment, body))
    }

    pub fn decode(&self, token: &str) -> Result<Jwt, Error> {
        let (header, payload, signature, _) = self.decode_segments(token)?;

        Ok(Jwt::new(header, payload, signature))
    }

    pub fn verify_time_opt(&self, token: &str, time: Option<SystemTime>) -> Result<Jwt, Error> {
        let (header, payload, signature, body) = self.decode_segments(token)?;

        if header.alg() != Some("RS256") && header.alg() != None {
            return Err(err::invalid(format!("Unsupported algorithm: {:?}", header.alg())));
        }

        let kid = header.kid().ok_or(err::key("No key id".to_string()))?;

        let key = self.key_by_id(kid).ok_or(err::key(format!("JWT key \"{:?}\" does not exists", kid)))?;

        // normalize parameters for non-standard implementations that use base64/standard instead of base64/url
        let raw_e = normalize_and_decode(&key.e).or_else(|e| Err(err::cert(format!("Failed to decode exponent: {:?}", e))))?;
        let raw_n = normalize_and_decode(&key.n).or_else(|e| Err(err::cert(format!("Failed to decode modulus: {:?}", e))))?;

        // remove leading zero from rsa parameters (causes key to be rejected by ring)
        let n = match (raw_n.first().cloned(), raw_n) {
            (Some(0), n) => { info!("removing loading zero from modulus"); n[1..n.len()].to_vec() },
            (     _ , n) => n
        };

        let e = match (raw_e.first().cloned(), raw_e) {
            (Some(0), e) => { info!("removing loading zero from exponent"); e[1..e.len()].to_vec() },
            (     _ , e) => e
        };

        verify_signature(&e, &n, &body, &signature)?;

        let jwt = Jwt::new(header, payload, signature);

        if let Some(time) = time {
            if jwt.expired_time(time).unwrap_or(false) {
                return Err(err::exp(format!("Token expired (exp={:?})", jwt.payload().expiry())));
            }
            if jwt.early_time(time).unwrap_or(false) {
                return Err(err::nbf(format!("Too early to use token (nbf={:?})", jwt.payload().not_before())));
            }
        }

        Ok(jwt)
    }

    pub fn verify_time(&self, token: &str, time: SystemTime) -> Result<Jwt, Error> {
        self.verify_time_opt(token, Some(time))
    }

    /// Verify a JWT token.
    /// If the token is valid, it is returned.
    ///
    /// A token is considered valid if:
    /// * Is well formed
    /// * Has a `kid` field that matches a public signature `kid
    /// * Signature matches public key
    /// * It is not expired
    /// * The `nbf` is not set to before now
    pub fn verify(&self, token: &str) -> Result<Jwt, Error> {
        self.verify_time(token, SystemTime::now())
    }

    /// Time at which the keys were last refreshed
    pub fn last_load_time(&self) -> Option<SystemTime> {
        self.load_time
    }

    /// True if the keys are expired and should be refreshed
    ///
    /// None if keys do not have an expiration time
    pub fn keys_expired(&self) -> Option<bool> {
        match self.expire_time {
            Some(expire) => Some(expire <= SystemTime::now()),
            None => None,
        }
    }

    /// Specifies the interval (as a fraction) when the key store should refresh it's key.
    ///
    /// The default is 0.5, meaning that keys should be refreshed when we are halfway through the expiration time (similar to DHCP).
    ///
    /// This method does _not_ update the refresh time. Call `load_keys` to force an update on the refresh time property.
    pub fn set_refresh_interval(&mut self, interval: f64) {
        self.refresh_interval = interval;
    }

    /// Get the current fraction time to check for token refresh time.
    pub fn refresh_interval(&self) -> f64 {
        self.refresh_interval
    }

    /// The time at which the keys were loaded
    /// None if the keys were never loaded via `load_keys` or `load_keys_from`.
    pub fn load_time(&self) -> Option<SystemTime> {
        self.load_time
    }

    /// Get the time at which the keys are considered expired
    pub fn expire_time(&self) -> Option<SystemTime> {
        self.expire_time
    }

    /// time at which keys should be refreshed.
    pub fn refresh_time(&self) -> Option<SystemTime> {
        self.refresh_time
    }

    /// Returns `Option<true>` if keys should be refreshed based on the given `current_time`.
    ///
    /// None is returned if the key store does not have a refresh time available. For example, the
    /// `load_keys` function was not called or the HTTP server did not provide a  
    pub fn should_refresh_time(&self, current_time: SystemTime) -> Option<bool> {
        if let Some(refresh_time) = self.refresh_time {
            return Some(refresh_time <= current_time);
        }

        None
    }

    /// Returns `Option<true>` if keys should be refreshed based on the system time.
    ///
    /// None is returned if the key store does not have a refresh time available. For example, the
    /// `load_keys` function was not called or the HTTP server did not provide a  
    pub fn should_refresh(&self) -> Option<bool> {
        self.should_refresh_time(SystemTime::now())
    }
}


fn verify_signature(e: &Vec<u8>, n: &Vec<u8>, message: &str, signature: &str) -> Result<(), Error> {
    let pkc = RsaPublicKeyComponents { e, n };

    let message_bytes = &message.as_bytes().to_vec();
    let signature_bytes = normalize_and_decode(signature).or_else(|e| Err(err::signature(format!("Could not base64 decode signature: {:?}", e))))?;

    // use RSA_PKCS1_512_8192_SHA256_FOR_LEGACY_USE_ONLY to allow validation of smaller keys
    let result = pkc.verify(&RSA_PKCS1_512_8192_SHA256_FOR_LEGACY_USE_ONLY, &message_bytes, &signature_bytes);

    result.or_else(|e| Err(err::cert(format!("Signature does not match certificate: {:?}", e))))
}

fn decode_segment<T: DeserializeOwned>(segment: &str) -> Result<T, Error> {
    let raw = normalize_and_decode(segment).or_else(|e| Err(err::invalid(format!("Failed to decode segment: {:?}", e))))?;
    let slice = String::from_utf8_lossy(&raw);
    let decoded: T = serde_json::from_str(&slice).or_else(|e| Err(err::invalid(format!("Failed to decode segment: {:?}", e))))?;

    Ok(decoded)
}
