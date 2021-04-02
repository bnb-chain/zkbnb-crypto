package okamoto

import (
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/ffmath"
	"math/big"
)

type P256 = zp256.P256

// prove \alpha,\beta st. U = g^{\alpha} h^{\beta}
func Prove(alpha, beta *big.Int, g, h *P256, U *P256) (a, z *big.Int, A *P256) {
	// at,bt \gets_R Z_p
	at := zp256.RandomValue()
	bt := zp256.RandomValue()
	// A = g^a h^b
	A = zp256.Add(zp256.ScalarBaseMult(at), zp256.ScalarHBaseMult(bt))
	// c = H(A,U)
	c := HashOkamoto(A, U)
	// a = at + c * alpha, z = bt + c * beta
	a = ffmath.Add(at, ffmath.Multiply(c, alpha))
	z = ffmath.Add(bt, ffmath.Multiply(c, beta))
	return a, z, A
}

func Verify(a, z *big.Int, g, h, A, U *P256) bool {
	// cal c = H(A,U)
	c := HashOkamoto(A, U)
	// check if g^a h^z = A * U^c
	l := zp256.Add(zp256.ScalarBaseMult(a), zp256.ScalarHBaseMult(z))
	r := zp256.Add(A, zp256.ScalarMult(U, c))
	return zp256.Equal(l, r)
}
