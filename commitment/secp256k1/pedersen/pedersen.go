package pedersen

import (
	"math/big"
	"zecrey-crypto/ecc/zp256"
)

type P256 = zp256.P256

func Commit(a *big.Int, r *big.Int, g, h *P256) *P256 {
	commitment := zp256.ScalarMul(g, a)
	commitment.Add(commitment, zp256.ScalarMul(h, r))
	return commitment
}
