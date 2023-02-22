pub(crate) fn block_count(len: usize, block_size: usize) -> usize {
    // Divide msg length by block size rounding up
    (len / block_size) + (len % block_size != 0) as usize
}
