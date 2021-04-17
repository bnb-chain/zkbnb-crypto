package pedersen

import (
	"zecrey-crypto/ecc/zp256"
	"math/big"
)

type P256 = zp256.P256

func Commit(a *big.Int, r *big.Int, g, h *P256) *P256 {
	commitment := zp256.ScalarMult(g, a)
	commitment = zp256.Add(commitment, zp256.ScalarMult(h, r))
	return commitment
}
