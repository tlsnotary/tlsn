//! Computation of HkdfLabel as specified in TLS 1.3.

use crate::FError;

use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        MemoryExt, Vector, ViewExt,
    },
    Vm,
};

/// Functionality for HkdfLabel computation.
#[derive(Debug)]
pub(crate) struct HkdfLabel {
    /// Cleartext label.
    label: HkdfLabelClear,
    // VM reference for the HKDF label.
    output: Vector<U8>,
    // Label context.
    ctx: Option<Vec<u8>>,
    state: State,
}

impl HkdfLabel {
    /// Allocates a new HkdfLabel.
    pub(crate) fn alloc(
        vm: &mut dyn Vm<Binary>,
        label: &'static [u8],
        ctx_len: usize,
        out_len: usize,
    ) -> Result<Self, FError> {
        let label_ref = vm
            .alloc_vec::<U8>(hkdf_label_length(label.len(), ctx_len))
            .map_err(FError::vm)?;
        vm.mark_public(label_ref).map_err(FError::vm)?;

        Ok(Self {
            label: HkdfLabelClear::new(label, out_len),
            output: label_ref,
            ctx: None,
            state: State::WantsContext,
        })
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        match self.state {
            State::WantsContext => self.is_ctx_set(),
            _ => false,
        }
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        if let State::WantsContext = &mut self.state {
            if let Some(ctx) = &self.ctx {
                self.label.set_ctx(ctx)?;

                vm.assign(self.output, self.label.output()?)
                    .map_err(FError::vm)?;
                vm.commit(self.output).map_err(FError::vm)?;

                self.state = State::Complete;
            }
        }

        Ok(())
    }

    /// Sets label context.
    pub(crate) fn set_ctx(&mut self, ctx: &[u8]) -> Result<(), FError> {
        if self.is_ctx_set() {
            return Err(FError::state("context has already been set"));
        }

        self.ctx = Some(ctx.to_vec());

        Ok(())
    }

    /// Returns the HkdfLabel output.
    pub(crate) fn output(&self) -> Vector<U8> {
        self.output
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }

    /// Returns whether context has been set.
    fn is_ctx_set(&self) -> bool {
        self.ctx.is_some()
    }
}

#[derive(Debug)]
enum State {
    /// Wants the context to be set.
    WantsContext,
    Complete,
}

/// Functionality for HkdfLabel computation on cleartext values.
#[derive(Debug)]
pub(crate) struct HkdfLabelClear {
    /// Human-readable label.
    label: &'static [u8],
    /// Context.
    ctx: Option<Vec<u8>>,
    /// Output length.
    out_len: usize,
}

impl HkdfLabelClear {
    /// Creates a new label.
    pub(crate) fn new(label: &'static [u8], out_len: usize) -> Self {
        Self {
            label,
            ctx: None,
            out_len,
        }
    }

    /// Sets label context.
    pub(crate) fn set_ctx(&mut self, ctx: &[u8]) -> Result<(), FError> {
        if self.ctx.is_some() {
            return Err(FError::state("context has already been set"));
        }

        self.ctx = Some(ctx.to_vec());
        Ok(())
    }

    /// Returns the byte representation of the label.
    pub(crate) fn output(&self) -> Result<Vec<u8>, FError> {
        match &self.ctx {
            Some(ctx) => Ok(make_hkdf_label(self.label, ctx, self.out_len)),
            _ => Err(FError::state("context was not set")),
        }
    }
}

/// Returns the byte representation of an HKDF label.
pub(crate) fn make_hkdf_label(label: &[u8], ctx: &[u8], out_len: usize) -> Vec<u8> {
    assert!(
        out_len <= 256,
        "output length larger than 256 not supported"
    );

    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let mut hkdf_label = Vec::new();
    let output_len = u16::to_be_bytes(out_len as u16);
    let label_len = u8::to_be_bytes((LABEL_PREFIX.len() + label.len()) as u8);
    let context_len = u8::to_be_bytes(ctx.len() as u8);

    hkdf_label.extend_from_slice(&output_len);
    hkdf_label.extend_from_slice(&label_len);
    hkdf_label.extend_from_slice(LABEL_PREFIX);
    hkdf_label.extend_from_slice(label);
    hkdf_label.extend_from_slice(&context_len);
    hkdf_label.extend_from_slice(ctx);
    hkdf_label
}

/// Returns the length of an HKDF label.
fn hkdf_label_length(label_len: usize, ctx_len: usize) -> usize {
    // 2 : output length as u16
    // 1 : label length as u8
    // 6 : length of "tls13 "
    // 1 : context length as u8
    // see `make_hkdf_label`
    2 + 1 + 6 + label_len + 1 + ctx_len
}

#[cfg(test)]
mod tests {
    use crate::kdf::expand::label::make_hkdf_label;

    #[test]
    fn test_make_hkdf_label() {
        for fixture in test_fixtures() {
            let (label, ctx, hkdf_label, out_len) = fixture;
            assert_eq!(make_hkdf_label(label, &ctx, out_len), hkdf_label);
        }
    }

    // Test vectors from https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors-06
    // (in that ref, `hash` is the context, `info` is the hkdf label).
    #[allow(clippy::type_complexity)]
    fn test_fixtures() -> Vec<(&'static [u8], Vec<u8>, Vec<u8>, usize)> {
        vec![
        (
            b"derived",
            from_hex_str("e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55"),
            from_hex_str("00 20 0d 74 6c 73 31 33 20 64 65 72 69 76 65 64 20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55"),
            32,
        ),
        (
            b"c hs traffic",
            from_hex_str("c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d"),
            from_hex_str("00 20 12 74 6c 73 31 33 20 63 20 68 73 20 74 72 61 66 66 69 63 20 c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d"),
            32,
        ),
        (
            b"s hs traffic",
            from_hex_str("c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d"),
            from_hex_str("00 20 12 74 6c 73 31 33 20 73 20 68 73 20 74 72 61 66 66 69 63 20 c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d"),
            32,
        ),
        (
            b"key",
            from_hex_str(""),
            from_hex_str("00 10 09 74 6c 73 31 33 20 6b 65 79 00"),
            16,
        ),
        (
            b"iv",
            from_hex_str(""),
            from_hex_str("00 0c 08 74 6c 73 31 33 20 69 76 00"),
            12,
        ),
        (
            b"finished",
            from_hex_str(""),
            from_hex_str("00 20 0e 74 6c 73 31 33 20 66 69 6e 69 73 68 65 64 00"),
            32,
        ),
        (
            b"c ap traffic",
            from_hex_str("f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf"),
            from_hex_str("00 20 12 74 6c 73 31 33 20 63 20 61 70 20 74 72 61 66 66 69 63 20 f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf"),
            32,
        ),
        (
            b"s ap traffic",
            from_hex_str("f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf"),
            from_hex_str("00 20 12 74 6c 73 31 33 20 73 20 61 70 20 74 72 61 66 66 69 63 20 f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf"),
            32,
        ),
        (
            b"exp master",
            from_hex_str("f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf"),
            from_hex_str("00 20 10 74 6c 73 31 33 20 65 78 70 20 6d 61 73 74 65 72 20 f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf"),
            32,
        ),
        (
            b"res master",
            from_hex_str("50 2f 86 b9 57 9e c0 53 d3 28 24 e2 78 0e f6 5c c4 37 a3 56 43 45 35 6b df 79 13 ec 3b 87 96 14"),
            from_hex_str("00 20 10 74 6c 73 31 33 20 72 65 73 20 6d 61 73 74 65 72 20 50 2f 86 b9 57 9e c0 53 d3 28 24 e2 78 0e f6 5c c4 37 a3 56 43 45 35 6b df 79 13 ec 3b 87 96 14"),
            32,
        ),
        (
            b"resumption",
            from_hex_str("00 00"),
            from_hex_str("00 20 10 74 6c 73 31 33 20 72 65 73 75 6d 70 74 69 6f 6e 02 00 00"),
            32,
        ),
    ]
    }

    fn from_hex_str(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }
}
