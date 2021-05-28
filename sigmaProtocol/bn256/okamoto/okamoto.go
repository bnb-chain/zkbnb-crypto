package okamoto

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/ffmath"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// prove \alpha,\beta st. U = g^{\alpha} h^{\beta}
func Prove(alpha, beta *big.Int, g, h *bn256.G1Affine, U *bn256.G1Affine) (a, z *big.Int, A *bn256.G1Affine) {
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

func Verify(a, z *big.Int, g, h, A, U *bn256.G1Affine) bool {
	// cal c = H(A,U)
	c := HashOkamoto(A, U)
	// check if g^a h^z = A * U^c
	l := zbn254.G1Add(zbn254.G1ScalarBaseMul(a), zbn254.G1ScalarHBaseMul(z))
	r := zbn254.G1Add(A, zbn254.G1ScalarMul(U, c))
	return l.Equal(r)
}
