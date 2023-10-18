use axum::{extract::State, http::Request};
use tracing::error;

use crate::{
    domain::{auth::AuthorizationWhitelistRecord, notary::NotaryGlobals},
    util::parse_csv_file,
};

pub async fn authorization_middleware<B>(
    State(notary_globals): State<NotaryGlobals>,
    request: Request<B>,
) -> Request<B> {
    let Some(whitelist_path) = notary_globals.authorization_whitelist_path else {
        return request;
    };
    let whitelist = match parse_csv_file::<AuthorizationWhitelistRecord>(&whitelist_path) {
        Ok(whitelist) => whitelist,
        Err(err) => {
            error!("Failed to parse authorization whitelist csv: {:?}", err);
            return request;
        }
    };

    todo!()
}
