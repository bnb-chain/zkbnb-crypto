package schnorr

import (
	"ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"math/big"
)

func HashSchnorr(A *P256, R *P256) *big.Int {
	ARBytes := util.ContactBytes(A.Bytes(), R.Bytes())
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
