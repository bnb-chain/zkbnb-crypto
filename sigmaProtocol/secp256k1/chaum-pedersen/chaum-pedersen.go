package chaum_pedersen

import (
	"Zecrey-crypto/ecc/zp256"
	"Zecrey-crypto/ffmath"
	"math/big"
)

type P256 = zp256.P256

// prove v = g^{\beta} \and w = u^{\beta}
func Prove(beta *big.Int, g, u, v, w *P256) (z *big.Int, Vt, Wt *P256) {
	// betat \gets_R Z_p
	betat := zp256.RandomValue()
	// Vt = g^{betat}
	Vt = zp256.ScalarMult(g, betat)
	// Wt = u^{betat}
	Wt = zp256.ScalarMult(u, betat)
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// z = betat + beta * c
	z = ffmath.Add(betat, ffmath.Multiply(c, beta))
	return z, Vt, Wt
}

func Verify(z *big.Int, g, u, Vt, Wt, v, w *P256) bool {
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// check if g^z = Vt * v^c
	l1 := zp256.ScalarMult(g, z)
	r1 := zp256.Add(Vt, zp256.ScalarMult(v, c))
	// check if u^z = Wt * w^c
	l2 := zp256.ScalarMult(u, z)
	r2 := zp256.Add(Wt, zp256.ScalarMult(w, c))
	return zp256.Equal(l1, r1) && zp256.Equal(l2, r2)
}
