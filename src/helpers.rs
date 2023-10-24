pub fn copy<T>(dst: &mut [T], src: &[T]) -> usize
where
    T: Copy,
{
    let len = core::cmp::min(src.len(), dst.len());
    dst[..len].copy_from_slice(&src[..len]);
    len
}
