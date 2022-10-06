mod sealed {
    pub trait Sealed {}
}

pub trait State: sealed::Sealed {}
