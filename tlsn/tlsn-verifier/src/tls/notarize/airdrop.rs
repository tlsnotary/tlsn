pub(crate) mod airdrop {

    use p256::pkcs8::der::asn1::Int;
    use reqwest::Response;
    use serde_json::Number;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use tlsn_core::{
        msg::{SessionTranscripts, SignedSessionHeader, TlsnMessage},
        HandshakeSummary, SessionHeader, Signature, Transcript,
    };
    use tracing::info;
    use uuid::Uuid;

    const MIN_FOLLOWERS: u64 = 0;
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

    pub(crate) fn parse_transcripts(session_transcripts: SessionTranscripts) -> (String, String) {
        let transcript_tx_str =
            String::from_utf8_lossy(session_transcripts.transcript_tx.data()).to_string();
        let transcript_rx_str =
            String::from_utf8_lossy(session_transcripts.transcript_rx.data()).to_string();

        //info!(" Received transcripts: {:?}", transcript_rx_str);

        let start_key = String::from("userName\":\"");
        let end_key = String::from("\"");
        let user_id: String = parse_value(transcript_rx_str, start_key, end_key);

        let start_key = String::from("host: ");
        let end_key = String::from("\r\n");
        let host: String = parse_value(transcript_tx_str, start_key, end_key);

        return (host, user_id);
    }

    pub(crate) fn parse_value(str: String, start_key: String, end_key: String) -> String {
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

    pub(crate) async fn insert_token(user_id: String, host: String, uuid: String) -> bool {
        info!("host {:?} user_id: {:?} uuid {:?}", host, user_id, uuid);

        if host != "www.kaggle.com" {
            return false;
        }

        let client = reqwest::Client::new();

        let mut map = HashMap::new();
        map.insert("claim_key", uuid);
        map.insert("user_id", user_id);
        //map.insert("user_id", "test".to_string());
        map.insert("website", host);

        let res = client
            .post("https://airdrop-server.fly.dev/insert-claim-key")
            .header(
                "Authorization",
                "56tkps/VSmPdGTjN/TaKLOPN9LlT8v9IO7FzUV+nOHA=",
            )
            .json(&map)
            .send()
            .await
            .unwrap();

        println!("status = {:?}", res.status());

        let resp_claim_insert: RespClaimInsert = res.json().await.unwrap();
        println!("res = {:#?}", resp_claim_insert);

        return resp_claim_insert.success;
    }

    pub(crate) async fn check_followers(user_id: String) -> bool {
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
    #[cfg(feature = "tracing")]
    mod test {
        use super::*;
        // use serde::Serialize;
        // use serde_json::json;

        #[test]
        #[cfg(feature = "tracing")]
        fn test_parse() {
            let json_str = String::from(
                r#"
            {
                "name": "John Doe",
                "age": 30,
                "email": "john.doe@example.com"
            }
        "#,
            );

            let start_key = String::from("name\": \"");
            let end_key = String::from("\"");

            let parsed_value: String = parse_value(json_str, start_key, end_key);
            println!("parsed_value: {}", parsed_value);
            assert!(parsed_value == "John Doe")
        }

        #[test]
        #[cfg(feature = "tracing")]
        fn test_parse_2() {
            let json_str = String::from(
                r#"
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: Fri, 14 Jun 2024 02:51:49 GMT\r\nTransfer-Encoding: chunked\r\nX-Frame-Options: SAMEORIGIN\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\nContent-Security-Policy: object-src 'none'; script-src 'nonce-ZUToT69xQ40F4JPtCyvLZw==' 'report-sample' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' https: http:; base-uri 'none'; report-uri https://csp.withgoogle.com/csp/kaggle/20201130; frame-src 'self' https://www.kaggleusercontent.com https://www.youtube.com/embed/ https://polygraph-cool.github.io https://www.google.com/recaptcha/ https://www.docdroid.com https://www.docdroid.net https://kaggle-static.storage.googleapis.com https://kkb-production.jupyter-proxy.kaggle.net https://kkb-production.firebaseapp.com https://kaggle-metastore.firebaseapp.com https://apis.google.com https://content-sheets.googleapis.com/ https://accounts.google.com/ https://storage.googleapis.com https://docs.google.com https://drive.google.com https://calendar.google.com/;\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nVia: 1.1 google\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\nConnection: close\r\n\r\n192\r\n{\"id\":21142885,\"displayName\":\"Zlim93200\",\"email\":\"batchtrain@gmail.com\",\"userName\":\"zlim93200\",\"thumbnailUrl\":\"https://storage.googleapis.com/kaggle-avatars/thumbnails/default-thumb.png\",\"profileUrl\":\"/zlim93200\",\"registerDate\":\"2024-06-04T16:22:44.700Z\",\"lastVisitDate\":\"2024-06-14T02:36:09.207Z\",\"statusId\":2,\"canAct\":true,\"canBeSeen\":true,\"thumbnailName\":\"default-thumb.png\",\"httpAcceptLanguage\":\"\"}\r\n0\r\n\r\n"
    "#,
            );

            // \"userName\":\"zlim93200\"
            let start_key = String::from("userName\\\":\\\"");
            let end_key = String::from("\\\",");

            let parsed_value: String = parse_value(json_str, start_key, end_key);

            println!("parsed_value: {}", parsed_value);
            assert!(parsed_value == "zlim93200")
        }

        #[tokio::test]
        #[cfg(feature = "tracing")]
        async fn test_request_claim() {
            let resp = reqwest::get("https://httpbin.org/ip")
                .await
                .unwrap()
                .json::<HashMap<String, String>>()
                .await
                .unwrap();
            println!("{resp:#?}");
        }

        #[tokio::test]
        #[cfg(feature = "tracing")]
        async fn test_insert_token() {
            let user_id = "Zlim93200".to_string();
            let host = "www.kaggle.com".to_string();
            let claim_token = "token123".to_string();

            let resp = insert_token(user_id, host, claim_token).await;
            println!("{resp:#?}");
        }

        #[tokio::test]
        #[cfg(feature = "tracing")]
        async fn test_check_followers() {
            let user_id = "Zlim93200".to_string();
            let result = check_followers(user_id).await;
            println!("result = {:?}", result);
            //assert!(result == 42, "Failed to grant claim token");
        }

        #[tokio::test]
        #[cfg(feature = "tracing")]
        async fn test_flow() {
            let user_id = "Zlim93200".to_string();
            let host = "www.kaggle.com".to_string();
            //let claim_token = "token123".to_string();
            let uuid = Uuid::new_v4().to_string();

            let is_valid = check_followers(user_id.clone()).await;
            println!("is_valid = {:?}", is_valid);

            if is_valid {
                let inserted = insert_token(user_id, host, uuid).await;
                println!("inserted = {:?}", inserted);
            }
            //assert!(result == 42, "Failed to grant claim token");
        }
    }
}
