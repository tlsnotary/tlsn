/// Extract expected variant of an enum and handle errors
///
/// This macro is intended to simplify extracting the expected message
/// when doing communication.
/// - The first argument is the expression, which is matched
/// - the second argument is the expected enum variant
/// - the last argument is error which is retuned when the expected message is not present
///
/// The error needs to implement From for std::io::Error
#[macro_export]
macro_rules! expect_msg_or_err {
    ($match: expr, $expected: path, $err: path) => {
        match $match {
            Some($expected(msg)) => Ok(msg),
            Some(other) => Err($err(other)),
            None => Err(From::from(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "stream closed unexpectedly",
            ))),
        }
    };
}
