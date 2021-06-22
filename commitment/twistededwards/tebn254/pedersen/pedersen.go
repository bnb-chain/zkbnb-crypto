package pedersen

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

type Point = curve.Point

/**
compute commitment of a: C = g^a h^r
@a: the value needs to be committed
@r: the random value
@g: group generator
@h: another group generator
*/
func Commit(a *big.Int, r *big.Int, g, h *Point) (*Point, error) {
	if a == nil || r == nil || g == nil || h == nil ||
		curve.IsZero(g) || curve.IsZero(h) {
		return nil, ErrParams
	}
	commitment := curve.ScalarMul(g, a)
	commitment.Add(commitment, curve.ScalarMul(h, r))
	return commitment, nil
}

/**
Open a commitment: C' = g^a h^r
@C: commitment
@a: the value that is already committed
@r: the random value that used to commit
@g: group generator
@h: another group generator
*/
func Open(C *Point, a, r *big.Int, g, h *Point) (bool, error) {
	if C == nil || a == nil || r == nil ||
		g == nil || h == nil ||
		!g.IsOnCurve() || !h.IsOnCurve() || curve.IsZero(g) || curve.IsZero(h) {
		return false, ErrParams
	}
	commitment := curve.ScalarMul(g, a)
	commitment.Add(commitment, curve.ScalarMul(h, r))
	if C.Equal(commitment) {
		return true, nil
	}
	return false, nil
}
