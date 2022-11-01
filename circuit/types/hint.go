package types

import (
	"bytes"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/ethereum/go-ethereum/crypto"
)

//func Keccak256(_ ecc.ID, inputs []*big.Int, outputs []*big.Int) error {
//	var buf bytes.Buffer
//	for i := 0; i < len(inputs); i++ {
//		buf.Write(inputs[i].FillBytes(make([]byte, 32)))
//	}
//	hashVal := crypto.Keccak256Hash(buf.Bytes())
//	result := outputs[0]
//	result.SetBytes(hashVal[:])
//	return nil
//}

func Keccak256(_ ecc.ID, inputs []*big.Int, outputs []*big.Int) error {
	var buf bytes.Buffer
	// first 4 elements are: BlockNumber, CreatedAt, OldStateRoot, NewStateRoot
	// we treat each of them as a 32-bytes variable
	for i := 0; i < 4; i++ {
		buf.Write(inputs[i].FillBytes(make([]byte, 32)))
	}

	// the last element is onChainOpsCount, we treat it as a 32-bytes variable
	// and other elements of inputs are tx pubdata. we arrange pubdata as bit, so
	// we need to convert every 8 elements into a 1 byte, and write it into buf
	for i := 4; i < len(inputs)-1; i = i + 8 {
		buf.Write(CovertBitsToBigInt(inputs[i : i+8]).FillBytes(make([]byte, 1)))
	}

	buf.Write(inputs[len(inputs)-1].FillBytes(make([]byte, 32)))
	// fmt.Printf("commitment is: %x\n", buf.Bytes())
	hashVal := crypto.Keccak256Hash(buf.Bytes())
	result := outputs[0]
	result.SetBytes(hashVal[:])
	// fmt.Printf("commitment hash is: %x\n", hashVal[:])
	return nil
}

func CovertBitsToBigInt(inputs []*big.Int) *big.Int {
	var res *big.Int = new(big.Int).SetInt64(0)
	var base *big.Int = new(big.Int).SetInt64(2)
	for i := 0; i < len(inputs); i++ {
		res.Mul(res, base).Add(res, inputs[i])
	}
	return res
}
