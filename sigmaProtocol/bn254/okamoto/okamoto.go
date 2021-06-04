package okamoto

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/ffmath"
)

// prove \alpha,\beta st. U = g^{\alpha} h^{\beta}
func Prove(alpha, beta *big.Int, g, h *bn254.G1Affine, U *bn254.G1Affine) (a, z *big.Int, A *bn254.G1Affine) {
	// at,bt \gets_R Z_p
	at := zbn254.RandomValue()
	bt := zbn254.RandomValue()
	// A = g^a h^b
	A = zbn254.G1Add(zbn254.G1ScalarBaseMul(at), zbn254.G1ScalarHBaseMul(bt))
	// c = H(A,U)
	c := HashOkamoto(A, U)
	// a = at + c * alpha, z = bt + c * beta
	a = ffmath.AddMod(at, ffmath.MultiplyMod(c, alpha, Order), Order)
	z = ffmath.AddMod(bt, ffmath.MultiplyMod(c, beta, Order), Order)
	return a, z, A
}

func Verify(a, z *big.Int, g, h, A, U *bn254.G1Affine) bool {
	// cal c = H(A,U)
	c := HashOkamoto(A, U)
	// check if g^a h^z = A * U^c
	l := zbn254.G1Add(zbn254.G1ScalarBaseMul(a), zbn254.G1ScalarHBaseMul(z))
	r := zbn254.G1Add(A, zbn254.G1ScalarMul(U, c))
	return l.Equal(r)
}
