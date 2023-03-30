# zkbnb-crypto

`zkbnb-crypto` is the crypto library for ZkBNB Protocol. It implements rollup block circuit and supports exporting groth16/plonk proving key, verifying key and solidity verifier contract.


## Getting Started
### Exporting groth16 proving/verifying key, verifier contract

```shell
go test -v ./circuit/solidity -run "^TestExportSol$" -timeout 600m -blocksizes=1 -batchsize=100000
```
After this command is finished, there will be generated files: 
* R1CS files `*.r1cs.*.save` 
* PK VK files `*.pk.*.save`, `*.vk.save` 
* Verifier contract `ZkBNBVerifier*.sol`


### Exporting plonk proving/verifying key, verifier contract

```
cd circuit/solidity;

go test -run TestExportSolPlonk -count=1 -timeout 99999s
```
After this command is finished, there will be 4 generated files: `zkbnb.pk_plonk`, `zkbnb.vk_plonk`, `zkbnb.srs_plonk` and `ZkBNBPlonkVerifier.sol`

**NOTICE**: The generated proving and verifying key shouldn't be used in production environment, it's only for test purpose.

## Contributions

Welcome to make contributions to `github.com/bnb-chain/zkbnb-crypto`. Thanks!

