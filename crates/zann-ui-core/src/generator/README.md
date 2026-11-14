# Client secret generator

`zann-ui-core::generator` is the canonical native-client owner of password and
passphrase options, defaults, bounds and generation. Rust shells call it
directly; non-Rust shells use the one-to-one `zann-ffi` projection. OS entropy
failure is an error with its source retained; no weak RNG or syllable fallback
exists. Invalid options are rejected rather than clamped or silently repaired.

Passwords contain at least one character from every enabled class, then fill
from their union and shuffle. Selection uses rejection sampling. This ensures
unbiased individual selections, not a uniform distribution over all compliant
passwords. Scratch secret buffers are zeroized and results redact Debug.

Passphrases select independently with replacement from all 7776 EFF words.
The default is six lowercase words separated by spaces (about 77.5 bits from
word selection). Optional capitalization is deterministic and adds no claimed
entropy. An optional random digit is appended to a randomly selected word.
Words are never truncated and repetitions are allowed. Separators are space,
period or underscore: hyphen is excluded because four dictionary entries are
hyphenated, so a separator never collides with a word.

## Bundled dictionary attribution

`eff_large_wordlist.txt` is the **unmodified EFF Long Wordlist** by the
Electronic Frontier Foundation, downloaded 2026-11-14:

- Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
- Background: https://www.eff.org/dice
- SHA-256: `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
  under [EFF's copyright policy](https://www.eff.org/copyright).

This attribution covers the dictionary; the Rust implementation remains MIT.
The dictionary ships in the binary: generation never downloads words or sends
generated values over the network.
