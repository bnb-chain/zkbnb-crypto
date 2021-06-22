package binary

import (
	"bytes"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func HashChallenge(ca, cb *Point) *big.Int {
	toBytes := util.ContactBytes(curve.ToBytes(ca),
		curve.ToBytes(cb))
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, zmimc.Hmimc)
	return c
}
