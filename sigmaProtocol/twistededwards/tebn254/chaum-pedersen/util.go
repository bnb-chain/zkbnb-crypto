package chaum_pedersen

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"zecrey-crypto/util"
)

func HashChaumPedersen(Vt, Wt, v, w *Point) *big.Int {
	toBytes := util.ContactBytes(Vt.Marshal(),
		Wt.Marshal(),
		v.Marshal(),
		w.Marshal())
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, zmimc.Hmimc)
	return c
}
