# Optimized FIPS202 for CKB-VM

This folder contains an optimized implementation of FIPS202 for CKB-VM. The original code comes from the reference implementation of SPHINCS+:

- <https://github.com/sphincs/sphincsplus/blob/master/ref/fips202.c>
- <https://github.com/sphincs/sphincsplus/blob/master/ref/fips202.h>

## The implementation includes the following functions:

- shake128
- shake256
- sha3_256
- sha3_512

Incremental absorption processes complete 64-bit lanes, while final padding and
output extraction operate directly on the state. Byte-aligned input and output
remain supported, including on big-endian hosts. Keccak uses XORs and rotations,
so the SHA-2 ADC fusion pattern does not apply to its permutation.

Build and benchmark with `make && make run`. Run `make check` for the separate C
regression tests covering all four functions, rate boundaries, incremental
absorption/squeezing, and unaligned buffers.
