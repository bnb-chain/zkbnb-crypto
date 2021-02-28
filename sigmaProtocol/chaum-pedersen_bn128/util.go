package chaum_pedersen_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

func HashChaumPedersen(Vt, Wt, v, w *bn256.G1Affine) *big.Int {
	toBytes := util.ContactBytes(bn128.ToBytes(Vt),
		bn128.ToBytes(Wt),
		bn128.ToBytes(v),
		bn128.ToBytes(w))
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
