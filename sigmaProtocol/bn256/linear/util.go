package linear

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

func HashLinear(UtArr, uArr []*bn256.G1Affine) *fr.Element {
	UtBytes := zbn256.VecToBytes(UtArr)
	uBytes := zbn256.VecToBytes(uArr)
	var buffer bytes.Buffer
	buffer.Write(UtBytes)
	buffer.Write(uBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return ffmath.FromBigInt(c)
}
