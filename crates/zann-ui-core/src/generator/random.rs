use super::GeneratorError;

pub(super) type Entropy<'a> = dyn FnMut(&mut [u8]) -> Result<(), getrandom::Error> + 'a;

/// The bound is internal: non-empty fixed alphabets or the bundled word list.
/// Reject the incomplete bucket rather than reducing every random integer
/// modulo the bound. Cap retries so a defective entropy source cannot hang UI.
pub(super) fn index(bound: usize, entropy: &mut Entropy<'_>) -> Result<usize, GeneratorError> {
    debug_assert!(bound > 0 && bound <= 7776);
    let range = u64::from(u32::MAX) + 1;
    let limit = range - range % bound as u64;
    for _ in 0..128 {
        let mut bytes = [0; 4];
        entropy(&mut bytes).map_err(GeneratorError::Randomness)?;
        let value = u64::from(u32::from_le_bytes(bytes));
        if value < limit {
            return Ok((value % bound as u64) as usize);
        }
    }
    Err(GeneratorError::RandomnessRejected)
}
