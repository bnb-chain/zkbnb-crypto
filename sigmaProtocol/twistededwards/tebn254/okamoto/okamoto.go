package okamoto

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
)

type Point = curve.Point

var (
	H = curve.H
)

// prove \alpha,\beta st. U = g^{\alpha} h^{\beta}
func Prove(alpha, beta *big.Int, g, h *Point, U *Point) (a, z *big.Int, A *Point) {
	// at,bt \gets_R Z_p
	at := curve.RandomValue()
	bt := curve.RandomValue()
	// A = g^a h^b
	A = curve.Add(curve.ScalarBaseMul(at), curve.ScalarMul(H, bt))
	// c = H(A,U)
	c := HashOkamoto(A, U)
	// a = at + c * alpha, z = bt + c * beta
	a = ffmath.Add(at, ffmath.Multiply(c, alpha))
	z = ffmath.Add(bt, ffmath.Multiply(c, beta))
	return a, z, A
}

func Verify(a, z *big.Int, g, h, A, U *Point) bool {
	// cal c = H(A,U)
	c := HashOkamoto(A, U)
	// check if g^a h^z = A * U^c
	l := curve.Add(curve.ScalarBaseMul(a), curve.ScalarMul(H, z))
	r := curve.Add(A, curve.ScalarMul(U, c))
	return l.Equal(r)
}
