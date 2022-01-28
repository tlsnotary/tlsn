use crate::block::Block;

#[derive(Clone, Debug, PartialEq)]
pub enum Wire {
    /// Representation of a Bool wire
    Bool(Block),
}

impl std::default::Default for Wire {
    fn default() -> Self {
        Wire::Bool(Block::default())
    }
}

impl Wire {
    /// Unpack the wire represented by a `Block`
    pub fn from_block(inp: Block) -> Self {
        Wire::Bool(inp)
    }

    /// Pack the wire into a `Block`.
    pub fn as_block(&self) -> Block {
        match self {
            Wire::Bool(b) => *b,
        }
    }
}
