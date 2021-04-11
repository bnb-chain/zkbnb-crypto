package binary

import (
	"Zecrey-crypto/util"
	"bytes"
	"crypto/sha256"
	"math/big"
)

func HashChallenge(ca, cb *P256) *big.Int {
	toBytes := util.ContactBytes(ca.Bytes(),
		cb.Bytes())
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
