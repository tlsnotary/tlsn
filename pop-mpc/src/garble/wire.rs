use crate::block::Block;

#[derive(Clone, Debug, PartialEq)]
pub struct WireLabel(usize, Block);

impl WireLabel {
    pub fn new(id: usize, block: Block) -> Self {
        WireLabel(id, block)
    }
    /// Pack the wire label into a `Block`.
    pub fn as_block(&self) -> Block {
        self.1
    }
}
