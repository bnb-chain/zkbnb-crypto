package schnorr

import (
	"bytes"
	"math/big"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func HashSchnorr(A *Point, R *Point) *big.Int {
	ARBytes := util.ContactBytes(A.Marshal(), R.Marshal())
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, zmimc.Hmimc)
	return c
}
