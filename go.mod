module github.com/bnb-chain/zkbnb-crypto

go 1.17

require (
	github.com/consensys/gnark v0.7.0
	github.com/consensys/gnark-crypto v0.7.0
	github.com/ethereum/go-ethereum v1.10.26
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.0
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/rs/zerolog v1.26.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.2.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/consensys/gnark => github.com/bnb-chain/gnark v0.7.1-0.20230202123546-e93f0af3da54

replace github.com/consensys/gnark-crypto => github.com/bnb-chain/gnark-crypto v0.7.1-0.20221116021202-8d6fc01ac262
