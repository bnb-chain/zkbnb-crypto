package linear_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

func HashLinear(UtArr, uArr []*bn256.G1Affine) *big.Int {
	UtBytes := bn128.VecToBytes(UtArr)
	uBytes := bn128.VecToBytes(uArr)
	var buffer bytes.Buffer
	buffer.Write(UtBytes)
	buffer.Write(uBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
