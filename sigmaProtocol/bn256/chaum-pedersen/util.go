package chaum_pedersen

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

func HashChaumPedersen(Vt, Wt, v, w *bn256.G1Affine) *fr.Element {
	toBytes := util.ContactBytes(zbn256.ToBytes(Vt),
		zbn256.ToBytes(Wt),
		zbn256.ToBytes(v),
		zbn256.ToBytes(w))
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return ffmath.FromBigInt(c)
}
