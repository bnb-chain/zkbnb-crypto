package chaum_pedersen

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/bn254"
	"math/big"
)

func HashChaumPedersen(Vt, Wt, v, w *bn254.G1Affine) *big.Int {
	toBytes := util.ContactBytes(zbn254.ToBytes(Vt),
		zbn254.ToBytes(Wt),
		zbn254.ToBytes(v),
		zbn254.ToBytes(w))
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
