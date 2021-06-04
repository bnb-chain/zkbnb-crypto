package linear

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/util"
)

func HashLinear(UtArr, uArr []*Point) *big.Int {
	UtBytes, _ := curve.VecToBytes(UtArr)
	uBytes, _ := curve.VecToBytes(uArr)
	var buffer bytes.Buffer
	buffer.Write(UtBytes)
	buffer.Write(uBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
