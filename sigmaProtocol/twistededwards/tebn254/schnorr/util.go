package schnorr

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"zecrey-crypto/util"
)

func HashSchnorr(A *Point, R *Point) *big.Int {
	ARBytes := util.ContactBytes(A.Marshal(), R.Marshal())
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
