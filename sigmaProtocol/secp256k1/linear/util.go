package linear

import (
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/util"
	"bytes"
	"crypto/sha256"
	"math/big"
)

func HashLinear(UtArr, uArr []*P256) *big.Int {
	UtBytes := zp256.VecToBytes(UtArr)
	uBytes := zp256.VecToBytes(uArr)
	var buffer bytes.Buffer
	buffer.Write(UtBytes)
	buffer.Write(uBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}