package chaum_pedersen

import (
	"ZKSneak-crypto/util"
	"bytes"
	"crypto/sha256"
	"math/big"
)

func HashChaumPedersen(Vt, Wt, v, w *P256) *big.Int {
	toBytes := util.ContactBytes(Vt.Bytes(),
		Wt.Bytes(),
		v.Bytes(),
		w.Bytes())
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}