package abi

import (
	"github.com/bnb-chain/zkbnb-crypto/legend/circuit/bn254/encode/abi"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

type KeccakCircuit struct {
	AbiId         frontend.Variable
	Values        []frontend.Variable // variable name
	Keccaa256Hash []frontend.Variable `gnark:",public"` // abi object
	Name          frontend.Variable   `gnark:",public"` // abi object
}

func init() {
	hint.Register(GenerateKeccakHint)
}

func (circuit *KeccakCircuit) Define(api frontend.API) error {
	encoder, err := abi.NewAbiEncoder(api, circuit.AbiId)
	if err != nil {
		return err
	}

	res, err := encoder.Pack(api, circuit.Name, circuit.Values...)
	if err != nil {
		return err
	}

	keccakRes, err := api.Compiler().NewHint(GenerateKeccakHint, 32, res...)

	for i := range keccakRes {
		api.AssertIsEqual(keccakRes[i], circuit.Keccaa256Hash[i])
	}
	return nil
}

func GenerateKeccakHint(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	preImageBytes := make([]byte, 0)

	for _, bi := range inputs {
		if len(bi.Bytes()) > 1 {
			continue
		}
		preImageBytes = append(preImageBytes, uint8(bi.Uint64()))
	}

	keccakSum := crypto.Keccak256(preImageBytes)
	for i := range keccakSum {
		results[i].SetUint64(uint64(keccakSum[i]))
	}
	return nil
}
