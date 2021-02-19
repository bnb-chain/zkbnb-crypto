package linear_bn128

import (
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

func HashLinear(UtArr, uArr []*bn256.G1Affine) *big.Int {
	var cBytes []byte
	for i := 0; i < len(UtArr); i++ {
		cBytes = append(cBytes, util.ContactBytes(bn128.ToBytes(UtArr[i]), bn128.ToBytes(uArr[i]))...)
	}
	var buffer bytes.Buffer
	buffer.Write(cBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
