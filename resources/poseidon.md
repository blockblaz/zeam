# SSZ Poseidon Hasher

> ⚠️ Not cryptographically reviewed. Use for development and testing only.

Zeam supports Poseidon2 as an alternative SSZ hash function, intended for
ZK-friendly state hashing. It is disabled by default.

## Enabling Poseidon

Pass `-Duse_poseidon=true` at build time:

```sh
zig build -Doptimize=ReleaseFast -Dgit_version="$(git rev-parse --short HEAD)" -Duse_poseidon=true
```

The default (SHA256) build remains:

```sh
zig build -Doptimize=ReleaseFast -Dgit_version="$(git rev-parse --short HEAD)"
```

## How It Works

SSZ inputs (arbitrary byte sequences) are packed into KoalaBear field elements
using 24-bit data legs before being passed to the Poseidon2-24 permutation.
This transformation is required to fit generic SSZ byte data into Poseidon's
prime field constraints.

The Poseidon2 implementation is validated against Plonky3 test vectors for
cross-language parity.
