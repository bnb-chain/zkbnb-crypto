package types

import (
	"bytes"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/ethereum/go-ethereum/crypto"
)

func Keccak256(_ ecc.ID, inputs []*big.Int, outputs []*big.Int) error {
	var buf bytes.Buffer
	for i := 0; i < len(inputs); i++ {
		buf.Write(inputs[i].FillBytes(make([]byte, 32)))
	}
	hashVal := crypto.Keccak256Hash(buf.Bytes())
	result := outputs[0]
	result.SetBytes(hashVal[:])
	return nil
}
