/// Extract expected variant of an enum and handle errors
///
/// This macro is intended to simplify extracting the expected message
/// when doing communication.
/// - The first argument is the expression, which is matched
/// - the second argument is the expected enum variant
#[macro_export]
macro_rules! expect_msg_or_err {
    ($stream:expr, $expected:path) => {
        match $stream.next().await {
            Some(Ok($expected(msg))) => Ok(msg),
            Some(Ok(other)) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected message: {:?}", other),
            )),
            Some(Err(e)) => Err(e),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "stream closed unexpectedly",
            )),
        }
    };
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    #[derive(Debug)]
    enum Msg {
        Foo(u8),
        Bar(u8),
    }

    #[tokio::test]
    async fn test_expect_msg_macro() -> std::io::Result<()> {
        let mut stream = Box::pin(futures::stream::once(async { Ok(Msg::Foo(0u8)) }));

        let _ = expect_msg_or_err!(stream, Msg::Foo).unwrap();

        let mut stream = Box::pin(futures::stream::once(async { Ok(Msg::Bar(0u8)) }));

        let err = expect_msg_or_err!(stream, Msg::Foo).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let mut stream = Box::pin(futures::stream::once(async {
            Err::<Msg, _>(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }));

        let err = expect_msg_or_err!(stream, Msg::Foo).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

        Ok(())
    }
}
