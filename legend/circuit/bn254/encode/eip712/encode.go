package eip712

import (
	"encoding/hex"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/encode/abi"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

type Eip712Circuit struct {
	AbiId         frontend.Variable
	Values        []frontend.Variable // variable name
	Keccaa256Hash []frontend.Variable `gnark:",public"` // abi object
	Name          frontend.Variable   `gnark:",public"` // abi object
	SIG           []frontend.Variable
	PK            []frontend.Variable // PK
}

func init() {
	hint.Register(GenerateKeccakHint)
}

func (circuit *Eip712Circuit) Define(api frontend.API) error {
	encoder, err := abi.NewAbiEncoder(api, circuit.AbiId)
	if err != nil {
		return err
	}

	res, err := encoder.Pack(api, circuit.Name, circuit.Values...)
	if err != nil {
		return err
	}

	innerKeccakRes, err := api.Compiler().NewHint(GenerateKeccakHint, 32, res...)

	prefix, err := hex.DecodeString(abi.HexPrefixAndEip712DomainKeccakHash)
	if err != nil {
		return err
	}
	prefixVariables := make([]frontend.Variable, len(prefix))
	for i := 0; i < len(prefix); i++ {
		prefixVariables[i] = prefix[i]
	}

	outerBytes := append(prefixVariables, innerKeccakRes...)
	keccakRes, err := api.Compiler().NewHint(GenerateKeccakHint, 32, outerBytes...)

	for i := range keccakRes {
		api.AssertIsEqual(keccakRes[i], circuit.Keccaa256Hash[i])
	}

	if err != nil {
		return err
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
