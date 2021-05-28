package pedersen

import (
	"math/big"
	"zecrey-crypto/ecc/ztwistededwards/tebn254"
)

type Point = tebn254.Point

// compute commitment of a
func Commit(a *big.Int, r *big.Int, g, h *Point) *Point {
	commitment := tebn254.ScalarMul(g, a)
	commitment.Add(commitment, tebn254.ScalarMul(h, r))
	return commitment
}

func Open(C *Point, a, r *big.Int, g, h *Point) bool {
	commitment := tebn254.ScalarMul(g, a)
	commitment.Add(commitment, tebn254.ScalarMul(h, r))
	if C.Equal(commitment) {
		return true
	}
	return false
}
