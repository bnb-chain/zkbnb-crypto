package linear

import (
	"PrivaL-crypto/ecc/zbn256"
	"PrivaL-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

func HashLinear(UtArr, uArr []*bn256.G1Affine) *big.Int {
	UtBytes := zbn256.VecToBytes(UtArr)
	uBytes := zbn256.VecToBytes(uArr)
	var buffer bytes.Buffer
	buffer.Write(UtBytes)
	buffer.Write(uBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
