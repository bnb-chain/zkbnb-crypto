package schnorr

import (
	"fmt"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
)

type Point = curve.Point

var Order = curve.Order

// want to prove R = base^x
func Prove(x *big.Int, base *Point, R *Point) (z *big.Int, A *Point) {
	// r
	r := curve.RandomValue()
	// A = base^r
	A = curve.ScalarMul(base, r)
	// c = H(A,r)
	c := HashSchnorr(A, R)
	// z = r + c*x
	z = ffmath.AddMod(r, ffmath.Multiply(c, x), Order)
	return z, A
}

// check base^z = A * r^c
func Verify(z *big.Int, A *Point, R *Point, base *Point) bool {
	// cal c = H(A,r)
	c := HashSchnorr(A, R)
	l := curve.ScalarMul(base, z)
	fmt.Println("l.x:", l.X.String())
	fmt.Println("l.y:", l.Y.String())
	r := curve.Add(A, curve.ScalarMul(R, c))
	return l.Equal(r)
}
