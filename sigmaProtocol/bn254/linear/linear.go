package linear

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/ffmath"
	"github.com/consensys/gnark-crypto/bn254"
	"math/big"
)

// u = \prod_{i=1}^n g_{i}^{x_i}
func Prove(xArr []*big.Int, gArr, uArr []*bn254.G1Affine) (zArr []*big.Int, UtArr []*bn254.G1Affine) {
	m := len(uArr)
	n := len(xArr)
	var xtArr []*big.Int
	for i := 0; i < n; i++ {
		xti := zbn254.RandomValue()
		xtArr = append(xtArr, xti)
	}
	for i := 0; i < m; i++ {
		var Uti *bn254.G1Affine
		for j := 0; j < n; j++ {
			if j == 0 {
				Uti = zbn254.G1ScalarMul(gArr[i*n+j], xtArr[j])
				continue
			}
			Uti = zbn254.G1Add(Uti, zbn254.G1ScalarMul(gArr[i*n+j], xtArr[j]))
		}
		UtArr = append(UtArr, Uti)
	}
	// c = HashLinear
	c := HashLinear(UtArr, uArr)
	for i := 0; i < n; i++ {
		zi := ffmath.AddMod(xtArr[i], ffmath.MultiplyMod(c, xArr[i], Order), Order)
		zArr = append(zArr, zi)
	}
	return zArr, UtArr
}

func Verify(zArr []*big.Int, gArr, uArr, UtArr []*bn254.G1Affine) bool {
	n := len(zArr)
	m := len(uArr)
	// cal c
	c := HashLinear(UtArr, uArr)
	for i := 0; i < m; i++ {
		var l, r *bn254.G1Affine
		for j := 0; j < n; j++ {
			if j == 0 {
				l = zbn254.G1ScalarMul(gArr[i*n+j], zArr[j])
				continue
			}
			l = zbn254.G1Add(l, zbn254.G1ScalarMul(gArr[i*n+j], zArr[j]))
		}
		r = zbn254.G1Add(UtArr[i], zbn254.G1ScalarMul(uArr[i], c))
		if !l.Equal(r) {
			return false
		}
	}
	return true
}
