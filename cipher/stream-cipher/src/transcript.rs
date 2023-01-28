use mpc_core::garble::{Label, LabelPair};

pub struct BlockTranscript {
    text: Vec<u8>,
    text_labels: Vec<Label>,
    output_text: Vec<u8>,
    ctr: u32,
}

impl BlockTranscript {
    pub fn new(text: Vec<u8>, text_labels: Vec<Label>, output_text: Vec<u8>, ctr: u32) -> Self {
        Self {
            text,
            text_labels,
            output_text,
            ctr,
        }
    }

    pub fn get_text(&self) -> &[u8] {
        &self.text
    }

    pub fn get_text_labels(&self) -> &[Label] {
        &self.text_labels
    }

    pub fn get_output_text(&self) -> &[u8] {
        &self.output_text
    }

    pub fn get_ctr(&self) -> u32 {
        self.ctr
    }
}

pub struct BlindBlockTranscript {
    len: usize,
    text_labels: Vec<LabelPair>,
    output_text: Vec<u8>,
    ctr: u32,
}

impl BlindBlockTranscript {
    pub fn new(len: usize, text_labels: Vec<LabelPair>, output_text: Vec<u8>, ctr: u32) -> Self {
        Self {
            len,
            text_labels,
            output_text,
            ctr,
        }
    }

    pub fn get_len(&self) -> usize {
        self.len
    }

    pub fn get_text_labels(&self) -> &[LabelPair] {
        &self.text_labels
    }

    pub fn get_output_text(&self) -> &[u8] {
        &self.output_text
    }

    pub fn get_ctr(&self) -> u32 {
        self.ctr
    }
}

#[derive(Clone)]
pub struct MessageTranscript {
    explicit_nonce: Vec<u8>,
    msg: Vec<u8>,
    msg_labels: Vec<Label>,
    output_msg: Vec<u8>,
}

impl MessageTranscript {
    pub fn new(explicit_nonce: Vec<u8>) -> Self {
        Self {
            explicit_nonce,
            msg: Vec::new(),
            msg_labels: Vec::new(),
            output_msg: Vec::new(),
        }
    }

    pub fn get_explicit_nonce(&self) -> &[u8] {
        &self.explicit_nonce
    }

    pub fn get_msg(&self) -> &[u8] {
        &self.msg
    }

    pub fn get_msg_labels(&self) -> &[Label] {
        &self.msg_labels
    }

    pub fn get_output_msg(&self) -> &[u8] {
        &self.output_msg
    }

    pub(crate) fn append(&mut self, block: BlockTranscript) {
        self.msg.extend(block.text);
        self.msg_labels.extend(block.text_labels);
        self.output_msg.extend(block.output_text);
    }
}

#[derive(Clone)]
pub struct BlindMessageTranscript {
    explicit_nonce: Vec<u8>,
    len: usize,
    msg_labels: Vec<LabelPair>,
    output_msg: Vec<u8>,
}

impl BlindMessageTranscript {
    pub fn new(explicit_nonce: Vec<u8>) -> Self {
        Self {
            explicit_nonce,
            len: 0,
            msg_labels: Vec::new(),
            output_msg: Vec::new(),
        }
    }

    pub fn get_explicit_nonce(&self) -> &[u8] {
        &self.explicit_nonce
    }

    pub fn get_len(&self) -> usize {
        self.len
    }

    pub fn get_msg_labels(&self) -> &[LabelPair] {
        &self.msg_labels
    }

    pub fn get_output_msg(&self) -> &[u8] {
        &self.output_msg
    }

    pub(crate) fn append(&mut self, block: BlindBlockTranscript) {
        self.len += block.get_len();
        self.msg_labels.extend(block.text_labels);
        self.output_msg.extend(block.output_text);
    }
}
