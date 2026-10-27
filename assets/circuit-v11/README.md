# Circuit v11 proving key (`pk.bin`)

Groth16 **proving key for spend circuit v11**: the `pk.bin` every wallet bundles to build spend proofs. The production server deliberately doesn't serve it (so a malicious server can't swap it); ship this file inside your app and pass its path as `Config.provingKeyPath`.

| | |
|---|---|
| File | `pk.bin` (compressed arkworks `ProvingKey<Bn254>`) |
| Size | 4,394,320 bytes |
| SHA-256 | `2f59e8bde11819b583d117fc75f1be3c7902aba2eb67e6436b3efad392372483` |
| Circuit | `v11`, 23,084 constraints, 3 public inputs (nullifier, current_month, revocation_root) |
| Server key | Built for the server OPRF key `641946251b0dd34a770b6a567cc393c281ee15c28e2a44743e24a1aeb1f8d695`, which is a constant inside the circuit |
| Matches server | Its embedded verifying key hashes (compressed) to `c2ed4f41c8bdffb1a9bccb5e9aaca9c7bda263d06f2b39b82ffadc3312a6db06`, which is `circuit.vk_sha256` in production `GET /v1/meta`. |

Verify after downloading:

```bash
shasum -a 256 pk.bin      # must print 2f59e8bde11819b583d117fc75f1be3c7902aba2eb67e6436b3efad392372483
```

A proving key is public by design (it's in every wallet that ships it); it contains no secret.

This key comes from a single-party setup. It will be replaced by the output of a multi-party ceremony (see [`ceremony/`](../../ceremony/) on the `ceremony-v11` branch) before public launch. The ceremony changes only this file and the server's verifying key; tokens, filters and the server key stay the same. When that happens, `circuit.vk_sha256` in `/v1/meta` changes, and spends made with this file stop verifying until the app ships the new one.

See [`docs/04-integration-guides.md`](../../docs/04-integration-guides.md#setup) for bundling it on Android and iOS.

Download link (raw file):
`https://github.com/vazertuche105/perseverus-sdk/raw/main/assets/circuit-v11/pk.bin`
