//! TLS Airdrop
//!
use super::sign_ed2559;
use axum::Error;
use p256::pkcs8::der::asn1::Int;
use reqwest::Response;
use serde_json::Number;
use sign_ed2559::SignerEd25519;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tlsn_core::RedactedTranscript;

use mpz_core::serialize::CanonicalSerialize;
use std::env;
use tlsn_core::{
    merkle::MerkleRoot,
    msg::{SessionTranscripts, SignedSessionHeader, TlsnMessage},
    HandshakeSummary, SessionHeader, Signature, Transcript,
};
use tracing::info;
use uuid::Uuid;

const MIN_FOLLOWERS: u64 = 0;

const AIRDROP_SERVER: &str = "https://airdrop-server.fly.dev";

#[allow(non_snake_case)]
#[derive(serde::Deserialize, Debug)]
struct RespFollowers {
    userId: u64,
}
#[allow(non_snake_case)]
#[derive(serde::Deserialize, Debug)]
struct RespProfile {
    displayName: String,
    userId: u64,
    usersFollowingMe: Vec<RespFollowers>,
}

#[allow(non_snake_case)]
#[derive(serde::Deserialize, Debug)]
struct RespClaimInsert {
    success: bool,
}

#[derive(serde::Deserialize, Debug)]
#[allow(non_snake_case)]
struct Claim {
    id: u64,
    user_id: String,
    website: String,
    claim_key: String,
    claimed: bool,
}

#[derive(serde::Deserialize, Debug)]
struct RespClaimView {
    claims: Vec<Claim>,
}
#[allow(non_snake_case)]
#[derive(serde::Deserialize, Debug)]
struct RespKaggle {
    userProfile: RespProfile,
}

impl RespKaggle {
    fn new() -> RespKaggle {
        RespKaggle {
            userProfile: RespProfile {
                displayName: String::new(),
                userId: 0,
                usersFollowingMe: Vec::new(),
            },
        }
    }
}

/// Parses the session transcripts to extract the host and user ID.
///
/// # Arguments
///
/// * `session_transcripts` - The session transcripts containing the transmitted and received data.
///
/// # Returns
///
/// A tuple containing the host and user ID as strings.
fn parse_transcripts(sent: String, rcv: String) -> (String, String) {
    // Define the keys to search for in the received transcript to extract the user ID
    let start_key = String::from("userName\":\"");
    let end_key = String::from("\"");
    let user_id: String = parse_value(rcv, start_key, end_key);

    // Define the keys to search for in the transmitted transcript to extract the host
    let start_key = String::from("host: ");
    let end_key = String::from("\r\n");
    let host: String = parse_value(sent, start_key, end_key);

    // Return the extracted host and user ID as a tuple
    return (host, user_id);
}

/// Inserts a claim key for a user on a specific host.
///
/// # Arguments
///
/// * `user_id` - The ID of the user.
/// * `host` - The host website.
/// * `uuid` - The claim key to be inserted.
///
/// # Returns
///
/// A boolean indicating whether the claim key was successfully inserted.
async fn insert_claim_key(user_id: String, host: String, uuid: String) -> bool {
    let client = reqwest::Client::new();

    let mut map = HashMap::new();
    map.insert("claim_key", uuid);
    map.insert("user_id", user_id);
    //map.insert("user_id", "test".to_string());
    map.insert("website", host);

    let url = format!("{:}/insert-claim-key", AIRDROP_SERVER);
    let airdrop_server_auth = std::env::var("AIRDROP_SERVER_AUTH").unwrap();

    let res = client
        .post(url)
        .header("Authorization", airdrop_server_auth)
        .json(&map)
        .send()
        .await
        .unwrap();

    //println!("status = {:?}", res.status());

    let resp_claim_insert: RespClaimInsert = res.json().await.unwrap();
    //println!("res = {:#?}", resp_claim_insert);

    return resp_claim_insert.success;
}

/// Views the claim key for a user.
///
/// # Arguments
///
/// * `user_id` - The ID of the user.
///
/// # Returns
///
/// A tuple containing a boolean indicating whether a claim key exists and the claim key as a string.
async fn view_claim_key(user_id: String) -> (bool, String) {
    let client = reqwest::Client::new();

    let mut map = HashMap::new();
    map.insert("user_id", user_id);

    let url = format!("{:}/view-user-claims", AIRDROP_SERVER);
    let airdrop_server_auth = std::env::var("AIRDROP_SERVER_AUTH").unwrap();
    let res = client
        .post(url)
        .header("Authorization", airdrop_server_auth)
        .json(&map)
        .send()
        .await
        .unwrap();

    //println!("status = {:?}", res.status());

    let resp_claim_insert: RespClaimView = res.json().await.unwrap();
    //println!("res = {:#?}", resp_claim_insert);

    if resp_claim_insert.claims.len() > 0 {
        return (true, resp_claim_insert.claims[0].claim_key.clone());
    } else {
        return (false, "".to_string());
    }
}

//@TODO : to remove, deprecated
/// Checks the number of followers for a given user.
///
/// # Arguments
///
/// * `user_id` - The ID of the user.
///
/// # Returns
///
/// A boolean indicating whether the user has the minimum required followers.
async fn check_followers(user_id: String) -> bool {
    let client = reqwest::Client::new();

    let mut map = HashMap::new();
    map.insert("relativeUrl", user_id.clone());

    let res = client
            .post("https://www.kaggle.com/api/i/routing.RoutingService/GetPageDataByUrl")
            .header("cookie", "ka_sessionid=6cff08a3142d89f9fe8e8232d101f5ec; CSRF-TOKEN=CfDJ8CHCUm6ypKVLpjizcZHPE706CGhBGw-qXt3fYKSnshHAHCz7JZRraz7CY0pF39jTcccPTjfh7sKqyoPMZ8DtjiKzjpJzophmKaNKY_cv2A; GCLB=CJD19dbEidGQ0wEQAw; build-hash=25329b9ee1e8ff6e9268ed171e37e91972f190cf; recaptcha-ca-t=AaGzOmdJKOWu-htf89JEBvCCVQMG1SteZS4dMNVE4o06Djc4hrVQSWeV1ygz4ZzvkaWwqviyUdt40OzDxW4K0-twsw_6UvvBtInLAWKsWhSNHMmVE7E3ddo0YPNkdvaLsaNkIMPDtZ8csqHM6g:U=e480c09ba0000000; XSRF-TOKEN=CfDJ8CHCUm6ypKVLpjizcZHPE70HA0syy35mtn6KbUjCbOddkpiyjjo1c-dvBq0e71nnCYWEOLl6qRVufWFyh5GeEdnzdiM-ZcrEz4EboI5lussb4w; CLIENT-TOKEN=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJrYWdnbGUiLCJhdWQiOiJjbGllbnQiLCJzdWIiOiIiLCJuYnQiOiIyMDI0LTA2LTE3VDE4OjA5OjI2LjkxMjczNzVaIiwiaWF0IjoiMjAyNC0wNi0xN1QxODowOToyNi45MTI3Mzc1WiIsImp0aSI6ImEwMWZjNWNkLTA0YjctNDFjMS05NjNmLTJiNDE2YWIxZjIwNSIsImV4cCI6IjIwMjQtMDctMTdUMTg6MDk6MjYuOTEyNzM3NVoiLCJhbm9uIjp0cnVlLCJmZiI6WyJLZXJuZWxzRmlyZWJhc2VMb25nUG9sbGluZyIsIkFsbG93Rm9ydW1BdHRhY2htZW50cyIsIkZyb250ZW5kRXJyb3JSZXBvcnRpbmciLCJSZWdpc3RyYXRpb25OZXdzRW1haWxTaWdudXBJc09wdE91dCIsIkRpc2N1c3Npb25zUmVhY3Rpb25zIiwiRGF0YXNldFVwbG9hZGVyRHVwbGljYXRlRGV0ZWN0aW9uIiwiRGF0YXNldHNMbG1GZWVkYmFja0NoaXAiLCJNZXRhc3RvcmVDaGVja0FnZ3JlZ2F0ZUZpbGVIYXNoZXMiLCJLTU1hdGVyaWFsVUlEaWFsb2ciLCJBbGxSb3V0ZXNUb1JlYWN0Um91dGVyIl0sImZmZCI6eyJLZXJuZWxFZGl0b3JBdXRvc2F2ZVRocm90dGxlTXMiOiIzMDAwMCIsIkVtZXJnZW5jeUFsZXJ0QmFubmVyIjoie30iLCJDbGllbnRScGNSYXRlTGltaXRRcHMiOiI0MCIsIkNsaWVudFJwY1JhdGVMaW1pdFFwbSI6IjUwMCIsIkZlYXR1cmVkQ29tbXVuaXR5Q29tcGV0aXRpb25zIjoiNjAwOTUsNTQwMDAsNTcxNjMsODA4NzQiLCJBZGRGZWF0dXJlRmxhZ3NUb1BhZ2VMb2FkVGFnIjoiZGlzYWJsZWQiLCJNb2RlbElkc0FsbG93SW5mZXJlbmNlIjoiMzMwMSwzNTMzIiwiTW9kZWxJbmZlcmVuY2VQYXJhbWV0ZXJzIjoieyBcIm1heF90b2tlbnNcIjogMTI4LCBcInRlbXBlcmF0dXJlXCI6IDAuNCwgXCJ0b3Bfa1wiOiA1IH0iLCJDb21wZXRpdGlvbk1ldHJpY1RpbWVvdXRNaW51dGVzIjoiMzAifSwicGlkIjoia2FnZ2xlLTE2MTYwNyIsInN2YyI6IndlYi1mZSIsInNkYWsiOiJBSXphU3lBNGVOcVVkUlJza0pzQ1pXVnotcUw2NTVYYTVKRU1yZUUiLCJibGQiOiIyNTMyOWI5ZWUxZThmZjZlOTI2OGVkMTcxZTM3ZTkxOTcyZjE5MGNmIn0.")
            .header("x-xsrf-token", "CfDJ8CHCUm6ypKVLpjizcZHPE70HA0syy35mtn6KbUjCbOddkpiyjjo1c-dvBq0e71nnCYWEOLl6qRVufWFyh5GeEdnzdiM-ZcrEz4EboI5lussb4w")
            .json(&map)
            .send()
            .await;

    let followers = match res {
        Ok(res) => {
            println!("status = {:?}", res.status());
            //assert!(res.status() == 200, "failed to retrieve user attributes");

            let resp_kaggle = RespKaggle::new();
            let val: RespKaggle = res.json().await.unwrap_or(resp_kaggle);

            let followers: u64 = val
                .userProfile
                .usersFollowingMe
                .len()
                .try_into()
                .unwrap_or(0);
            followers
        }
        Err(err) => {
            //info!("error when querying kaggle attributes {:}", err);
            0
            //panic!("request to kaggle failed");
        }
    };

    println!(" {:?} followers > {:?}", followers, MIN_FOLLOWERS);

    return followers >= MIN_FOLLOWERS;

    //info!("result = {:?}", result);
}

/// Parses a value from a string based on start and end keys.
///
/// # Arguments
///
/// * `str` - The string to parse the value from.
/// * `start_key` - The key indicating the start of the value.
/// * `end_key` - The key indicating the end of the value.
///
/// # Returns
///
/// The parsed value as a string. If the value cannot be found, an empty string is returned.
fn parse_value(str: String, start_key: String, end_key: String) -> String {
    let key = String::from(start_key);

    let parsed_value: String = match str.find(&key) {
        Some(start_pos) => {
            let start = start_pos + key.len();
            let end_pos = str[start..].find(&end_key).unwrap();
            str[start..start + end_pos].to_string()
        }
        err => {
            println!("error parsing value from transcript");
            println!("{:?}", err);
            "".to_string()
            //panic()! uncomment in production
        }
    };
    parsed_value
}

/// @WARNING: deprecated, to remove
pub async fn generate_claim_key(
    sent_transcript: RedactedTranscript,
    recv_transcript: RedactedTranscript,
    server_name: String,
) -> (String, bool) {
    let rcv = String::from_utf8(recv_transcript.data().to_vec())
        .unwrap_or("Could not convert sent data to string".to_string());
    let sent = String::from_utf8(sent_transcript.data().to_vec())
        .unwrap_or("Could not convert sent data to string".to_string());

    //parse
    //let host = parse_value(sent, "host: ".to_string(), "\r".to_string());
    let user_id = parse_value(rcv, "id\":".to_string(), ",".to_string());
    println!("user_id = {:?}", user_id);

    //check validity of attribute
    let mut is_valid = check_followers(user_id.clone()).await;
    let (has_claim_key, mut claim_key) = view_claim_key(user_id.clone()).await;

    if is_valid && !has_claim_key {
        println!("✅ valid user_id, inserting claim key...");
        claim_key = Uuid::new_v4().to_string();
        println!("🔑 claim_key = {:}", claim_key);
        let inserted =
            insert_claim_key(user_id.clone(), server_name.clone(), claim_key.clone()).await;
        println!(
            "{:?} claim_token inserted ",
            if inserted { "🟢 " } else { "❌ " }
        );

        if !inserted {
            is_valid = false;
        }
    } else if has_claim_key {
        println!("🟠 User already has already ");
    } else {
        println!("❌ invalid user_id");
    }

    (claim_key, is_valid)
}

use ed25519_dalek::Signature as Ed25519Signature;

/// @NOTE: new method: the notary doesn't query the follower of users
///
/// This function generates a signature for a user ID extracted from the received transcript.
/// It first converts the received transcript to a UTF-8 string, then parses the user ID from it.
/// If the user does not already have a claim key, it inserts a new claim key and generates a signature.
///
/// # Arguments
///
/// * `recv_transcript` - The received transcript containing the user ID.
/// * `server_name` - The name of the server.
///
/// # Returns
///
/// A string containing the generated signature, or an empty string if the user already has a claim key.
pub async fn generate_signature_userid(
    recv_transcript: RedactedTranscript,
    attr_transcript: RedactedTranscript,
    server_name: String,
    merkle_root: &MerkleRoot,
) -> Result<String, Error> {
    // Convert the received transcript to a UTF-8 string
    let auth_rcv = String::from_utf8(recv_transcript.data().to_vec())
        .unwrap_or("Could not convert sent data to string".to_string());

    let attr_rcv = String::from_utf8(attr_transcript.data().to_vec())
        .unwrap_or("Could not convert sent data to string".to_string());

    // Parse the user ID from the received transcripts
    let user_id = parse_value(auth_rcv, "id\":".to_string(), ",".to_string());

    let user_id_2 = parse_value(attr_rcv, "id\":".to_string(), ",".to_string());

    println!("user_id = {:} user_id_2 = {:}", user_id, user_id_2);

    if user_id != user_id_2 {
        return Err(Error::new(format!(
            "User ID mismatch between auth and attribute requests {} {}",
            user_id, user_id_2
        )));
    }

    // Check if the user already has a claim key
    let (has_claim_key, mut claim_key) = view_claim_key(user_id.clone()).await;

    if !has_claim_key {
        // If the user does not have a claim key, insert a new claim key
        println!("✅ valid user_id, inserting in DB...");
        claim_key = Uuid::new_v4().to_string(); //@TODO : claimkey is useless now, need to remove
        println!("🔑 params : {:} {:} {:} ", claim_key, user_id, server_name);
        let inserted =
            insert_claim_key(user_id.clone(), server_name.clone(), claim_key.clone()).await;
        println!("{} inserted ", if inserted { "🟢" } else { "❌" });

        if !inserted {
            return Err(Error::new("Not inserted"));
        }

        // Convert merkle_root to bytes

        // If the claim key was successfully inserted, generate a signature
        let private_key_env: String = std::env::var("NOTARY_PRIVATE_KEY_SECP256k1").unwrap();
        let signer = SignerEd25519::new(private_key_env);

        // We create a nullifier of user_id
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(user_id.as_bytes());
        let nullifier = hasher.finalize();
        let nullifier_vec = nullifier.to_vec();

        // Concatenate bytes of user_id and merkle_root.to_bytes() in one variable
        let mut combined_bytes = nullifier_vec.to_vec();
        combined_bytes.extend_from_slice(&merkle_root.to_bytes());

        // Sign the combined bytes
        let signature: Ed25519Signature = signer.sign(combined_bytes);
        info!("signature {}", signature.to_string());

        return Ok(signature.to_string());
    } else {
        // If the user already has a claim key, return an empty string
        println!("🟠 User_id already inserted");
        return Ok("".to_string());
    }
}

mod test {
    use super::*;
    // use serde::Serialize;
    // use serde_json::json;

    #[test]

    fn test_parsing() {
        let json_str = String::from(
            r#"
            XXXXXXX"id":21142885,XXXXXXXXXX
            "#,
        );

        // \"userName\":\"zlim93200\"
        let start_key = String::from("id\":");
        let end_key = String::from(",");

        let parsed_value: String = parse_value(json_str, start_key, end_key);

        println!("parsed_value: {}", parsed_value);
        //assert!(parsed_value == "zlim93200")
    }

    #[tokio::test]

    async fn test_insert_claim_key() {
        let user_id = "Zlim93200".to_string().to_lowercase();
        let host = "www.kaggle.com".to_string();
        let claim_token = "token123".to_string();

        let resp = insert_claim_key(user_id, host, claim_token).await;
        println!("{resp:#?}");
    }

    #[tokio::test]

    async fn test_view_claim_key() {
        let user_id = "Zlim93200".to_string().to_lowercase();

        let resp = view_claim_key(user_id).await;
        println!("{resp:#?}");
    }

    #[tokio::test]

    async fn test_check_followers() {
        let user_id = "Zlim93200".to_string();
        let result = check_followers(user_id).await;
        println!("result = {:?}", result);
        //assert!(result == 42, "Failed to grant claim token");
    }

    #[tokio::test]

    async fn test_flow() {
        let user_id = "Zlim93200".to_string();
        let host = "www.kaggle.com".to_string();
        //let claim_token = "token123".to_string();
        let uuid = Uuid::new_v4().to_string();

        let is_valid = check_followers(user_id.clone()).await;
        println!("is_valid = {:?}", is_valid);

        if is_valid {
            let inserted = insert_claim_key(user_id, host, uuid).await;
            println!("inserted = {:?}", inserted);
        }
        //assert!(result == 42, "Failed to grant claim token");
    }
}
