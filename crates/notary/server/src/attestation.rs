use sgx_dcap_ql_rs::{sgx_report_t, quote3_error_t, sgx_target_info_t};
use tracing::{ debug, instrument };
use axum::{
    extract::State,
    http::StatusCode,
    response::{ IntoResponse, Response },
};
use crate::error::NotaryServerError;
use crate::domain::notary::NotaryGlobals;
use axum_macros::debug_handler;

#[instrument(level = "debug", skip_all)]
pub async fn sgx_quote(State(_notary_globals): State<NotaryGlobals>) -> Result<
    Option<Vec<u8>>,
    quote3_error_t
> {
    let sgx_report:sgx_report_t = Default::default();

    let (result, sgx_quote) = sgx_dcap_ql_rs::sgx_qe_get_quote(&sgx_report);

    if result != sgx_dcap_ql_rs::quote3_error_t::SGX_QL_SUCCESS {
        error!("Failed to retrieve quote: {:?}", result);
        Err(result)
    }

    match sgx_quote {
        Some(q) => {
            debug!("Quote data: {:?}", q);
            Ok(Some(q))
        }
        None => {
            debug!("Failed to retrieve quote.");
            Err(quote3_error_t::SGX_QL_ERROR_UNEXPECTED)
        }
    }
}

#[debug_handler(state = NotaryGlobals)]
pub async fn get_quote(State(notary_globals): State<NotaryGlobals>) -> Response {

    let mut target_info: sgx_target_info_t = Default::default();
    let _result = sgx_dcap_ql_rs::sgx_qe_get_target_info(&mut target_info);



    match sgx_quote(State(notary_globals)).await {
        Ok(_) => { (StatusCode::OK, "Quote retrieved successfully").into_response() }
        Err(_) => {
            NotaryServerError::BadProverRequest("Failed to get quote".to_owned()).into_response()
        }
    }
}
