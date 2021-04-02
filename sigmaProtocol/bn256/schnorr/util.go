package schnorr

import (
	"PrivaL-crypto/ecc/zbn256"
	"PrivaL-crypto/util"
	"bytes"
	"crypto/sha256"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

func HashSchnorr(A *bn256.G1Affine, R *bn256.G1Affine) *big.Int {
	ARBytes := util.ContactBytes(zbn256.ToBytes(A), zbn256.ToBytes(R))
	var buffer bytes.Buffer
	buffer.Write(ARBytes)
	c, _ := util.HashToInt(buffer, sha256.New)
	return c
}
