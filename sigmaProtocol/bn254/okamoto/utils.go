package okamoto

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/bn254"
	"math/big"
)

func HashOkamoto(A *bn254.G1Affine, U *bn254.G1Affine) *big.Int {
	ARBytes := util.ContactBytes(zbn254.ToBytes(A), zbn254.ToBytes(U))
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}