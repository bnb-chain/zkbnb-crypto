# zkbas-crypto

`zkbas-crypto` is the crypto library for ZkBAS Protocol. It implements rollup block circuit and supports exporting groth16/plonk proving key, verifying key and solidity verifier contract.


## Getting Started
### Exporting groth16 proving/verifying key, verifier contract


```
cd legend/circuit/bn254/solidity;

go test -run TestExportSolGroth16  -count=1 -timeout 99999s
```
After this command is finished, there will be 3 generated files: `zkbas.pk_groth16`, `zkbas.vk_groth16` and `ZkbasVerifier.sol`


### Exporting plonk proving/verifying key, verifier contract

```
cd legend/circuit/bn254/solidity;

go test -run TestExportSolPlonk -count=1 -timeout 99999s
```
After this command is finished, there will be 4 generated files: `zkbas.pk_plonk`, `zkbas.vk_plonk`, `zkbas.srs_plonk` and `ZkbasPlonkVerifier.sol`

**NOTICE**: The generated proving and verifying key shouldn't be used in production environment, it's only for test purpose.

## Contributions

Welcome to make contributions to `github.com/bnb-chain/zkbas-crypto`. Thanks!

