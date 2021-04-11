package okamoto

import (
	"Zecrey-crypto/util"
	"bytes"
	"crypto/sha256"
	"math/big"
)

func HashOkamoto(A *P256, U *P256) *big.Int {
	ARBytes := util.ContactBytes(A.Bytes(), U.Bytes())
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}