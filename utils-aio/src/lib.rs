pub mod codec;

#[macro_export]
/// Convenience macro for reading and unwrapping an expected message from a stream which
/// implements [`futures::StreamExt`]. The caller function must be fallible and provide [`From<std::io::Error>`].
macro_rules! expected_msg {
    ($stream:expr, $expected:path) => {
        if let Some(msg) = $stream.next().await {
            match msg? {
                $expected(m) => Ok(m),
                msg => Err(msg),
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Stream closed unexpectedly",
            ))?
        }
    };
}
