package linear

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/bn254"
	"math/big"
)

func HashLinear(UtArr, uArr []*bn254.G1Affine) *big.Int {
	UtBytes := zbn254.VecToBytes(UtArr)
	uBytes := zbn254.VecToBytes(uArr)
	var buffer bytes.Buffer
	buffer.Write(UtBytes)
	buffer.Write(uBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
