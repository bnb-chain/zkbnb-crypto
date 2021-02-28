package okamoto_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

func HashOkamoto(A *bn256.G1Affine, U *bn256.G1Affine) *big.Int {
	ARBytes := util.ContactBytes(bn128.ToBytes(A), bn128.ToBytes(U))
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
