package schnorr

import (
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/ffmath"
	"math/big"
)

type P256 = zp256.P256

// want to prove R = base^x
func Prove(x *big.Int, base *P256, R *P256) (z *big.Int, A *P256) {
	// r
	r := zp256.RandomValue()
	// A = base^r
	A = zp256.ScalarMult(base, r)
	// c = H(A,r)
	c := HashSchnorr(A, R)
	// z = r + c*x
	z = ffmath.AddMod(r, ffmath.MultiplyMod(c, x, Order), Order)
	return z, A
}

// check base^z = A * r^c
func Verify(z *big.Int, A *P256, R *P256, base *P256) bool {
	// cal c = H(A,r)
	c := HashSchnorr(A, R)
	l := zp256.ScalarMult(base, z)
	r := zp256.Add(A, zp256.ScalarMult(R, c))
	return zp256.Equal(l, r)
}
