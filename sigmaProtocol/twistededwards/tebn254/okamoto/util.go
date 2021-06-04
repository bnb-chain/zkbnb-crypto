package okamoto

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"zecrey-crypto/util"
)

func HashOkamoto(A *Point, U *Point) *big.Int {
	ARBytes := util.ContactBytes(A.Marshal(), U.Marshal())
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, zmimc.Hmimc)
	return c
}
