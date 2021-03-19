package okamoto

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

func HashOkamoto(A *bn256.G1Affine, U *bn256.G1Affine) *fr.Element {
	ARBytes := util.ContactBytes(zbn256.ToBytes(A), zbn256.ToBytes(U))
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return ffmath.FromBigInt(c)
}
