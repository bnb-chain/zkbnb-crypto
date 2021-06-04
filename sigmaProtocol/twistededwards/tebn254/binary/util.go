package binary

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/util"
)

func HashChallenge(ca, cb *Point) *big.Int {
	toBytes := util.ContactBytes(curve.ToBytes(ca),
		curve.ToBytes(cb))
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
