# Vendored s2n-bignum (arm64, P-256)

Upstream: <https://github.com/awslabs/s2n-bignum>, commit `4d1356a7470663c752660a59375dc3a9ef548428`
(2026-09-29). Licence: Apache-2.0 OR ISC OR MIT-0 (`LICENSE`, `NOTICE` alongside;
this directory is the only part of `eventchain-crypto` not under the package's
BSD-3-Clause).

Files are byte-for-byte copies; nothing here is edited. Each `.S` is
self-contained (its subroutines are local clones) and includes only
`_internal_s2n_bignum_arm.h`, which selects the Darwin or ELF symbol
directives. The set is exactly the functions the ECDSA-P256 verification
kernel calls, not the whole of upstream's `arm/p256/`:

| upstream path | purpose |
| --- | --- |
| `arm/p256/p256_scalarmulbase.S` | fixed-base scalar multiplication from a caller-built table |
| `arm/p256/p256_montjmixadd.S`, `p256_montjdouble.S` | point arithmetic for the table build and the final sum |
| `arm/p256/bignum_montinv_p256.S`, `bignum_montmul_p256.S`, `bignum_montsqr_p256.S` | field arithmetic, Montgomery domain |
| `arm/p256/bignum_tomont_p256.S`, `bignum_demont_p256.S` | Montgomery domain in and out |
| `arm/p256/bignum_mod_n256.S`, `bignum_mod_n256_4.S` | reduction mod the group order |
| `arm/p256/bignum_bigendian_4.S`, `bignum_nonzero_4.S` | wire bytes to limbs, zero test |
| `arm/fastmul/bignum_mul_4_8.S` | 256×256-bit product, for scalars mod n |
| `arm/generic/bignum_modinv.S`, `bignum_eq.S`, `bignum_lt.S` | inverse mod n, comparisons |
| `include/_internal_s2n_bignum_arm.h` | symbol directives |
| `include/s2n-bignum.h` | the C prototypes the `capi` imports are checked against, through `../eventchain-s2n-bignum.h`, which only adds the include guard upstream's lacks |

To refresh: check out the upstream commit, copy the files named above from
`arm/<dir>/` into `arm/` here and the header into `include/`, copy `LICENSE`
and `NOTICE`, and update the commit hash above. The `_alt` twins are tuned
for other microarchitectures and are not used; x86-64 twins live under
upstream's `x86/` and are not vendored until a build has run there
(`tested-with` lists what is built).
