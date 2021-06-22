package chaum_pedersen

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
)

type Point = curve.Point

var (
	G     = curve.G
)

// prove v = g^{\beta} \and w = u^{\beta}
func Prove(beta *big.Int, g, u, v, w *Point) (z *big.Int, Vt, Wt *Point) {
	// betat \gets_R Z_p
	betat := curve.RandomValue()
	// Vt = g^{betat}
	Vt = curve.ScalarMul(g, betat)
	// Wt = u^{betat}
	Wt = curve.ScalarMul(u, betat)
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// z = betat + beta * c
	z = ffmath.Add(betat, ffmath.Multiply(c, beta))
	return z, Vt, Wt
}

func Verify(z *big.Int, g, u, Vt, Wt, v, w *Point) bool {
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// check if g^z = Vt * v^c
	l1 := curve.ScalarMul(g, z)
	r1 := curve.Add(Vt, curve.ScalarMul(v, c))
	// check if u^z = Wt * w^c
	l2 := curve.ScalarMul(u, z)
	r2 := curve.Add(Wt, curve.ScalarMul(w, c))
	return l1.Equal(r1) && l2.Equal(r2)
}
