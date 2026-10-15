# Circuit v10 proving key (`pk.bin`)

Groth16 **proving key for spend circuit v10**: the `pk.bin` every wallet bundles to build spend proofs. The production server deliberately doesn't serve it (so a malicious server can't swap it); ship this file inside your app and pass its path as `Config.provingKeyPath`.

| | |
|---|---|
| File | `pk.bin` (compressed arkworks `ProvingKey<Bn254>`) |
| Size | 4,133,200 bytes |
| SHA-256 | `ca79225709f48f20ab00549d51d6876e91a383047b13083846e85d326f8b909b` |
| Circuit | `v10`, 20,670 constraints, 3 public inputs (nullifier, current_month, revocation_root) |
| Matches server | Its embedded verifying key hashes (compressed) to `11a3a90c43089b3510185c61dd24d4c886fa592d037fe1717e6e6c936b88b103`, which is `circuit.vk_sha256` in production `GET /v1/meta`. |

Verify after downloading:

```bash
shasum -a 256 pk.bin      # must print ca79225709f48f20ab00549d51d6876e91a383047b13083846e85d326f8b909b
```

A proving key is public by design (it's in every wallet that ships it); it contains no secret. A new file will be released with a new tag if the circuit version changes, so check `circuit.version` in `/v1/meta`.

See [`docs/04-integration-guides.md`](../../docs/04-integration-guides.md#setup) for bundling it on Android and iOS.

Download link (raw file):
`https://github.com/vazertuche105/perseverus-sdk/raw/main/assets/circuit-v10/pk.bin`
