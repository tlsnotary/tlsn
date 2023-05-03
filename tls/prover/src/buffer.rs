//pub struct ExchangeBuffer {
//    request_buffer: AtomicByteBuffer,
//    response_buffer: AtomicByteBuffer,
//}
//
//impl ExchangeBuffer {
//    pub fn new() -> Self {
//        Self {
//            request_buffer: AtomicByteBuffer::new(4096),
//            response_buffer: AtomicByteBuffer::new(4096),
//        }
//    }
//
//    pub fn request_buffer(&self) -> &AtomicByteBuffer {
//        &self.request_buffer
//    }
//
//    pub fn response_buffer(&self) -> &AtomicByteBuffer {
//        &self.response_buffer
//    }
//
//    pub async fn make_request<T: Into<Vec<u8>>>(&self, _request: T) -> Result<(), BufferError> {
//        todo!();
//    }
//
//    pub async fn receive_response<'a, T: From<&'a [u8]>>() -> Result<T, BufferError> {
//        todo!();
//    }
//}
