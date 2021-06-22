package okamoto

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func HashOkamoto(A *bn254.G1Affine, U *bn254.G1Affine) *big.Int {
	ARBytes := util.ContactBytes(zbn254.ToBytes(A), zbn254.ToBytes(U))
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, zmimc.Hmimc)
	return c
}
