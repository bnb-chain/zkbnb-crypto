package linear_bn128

import (
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/ffmath"
	"crypto/rand"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

func Prove(xArr []*big.Int, gArr, uArr []*bn256.G1Affine) (zArr []*big.Int, UtArr []*bn256.G1Affine) {
	m := len(uArr)
	n := len(xArr)
	var xtArr []*big.Int
	for i := 0; i < n; i++ {
		xti, _ := rand.Int(rand.Reader, ORDER)
		xtArr = append(xtArr, xti)
	}
	for i := 0; i < m; i++ {
		var Uti *bn256.G1Affine
		for j := 0; j < n; j++ {
			if j == 0 {
				Uti = new(bn256.G1Affine).ScalarMultiplication(gArr[i*n+j], xtArr[j])
				continue
			}
			Uti = bn128.G1AffineMul(Uti, new(bn256.G1Affine).ScalarMultiplication(gArr[i*n+j], xtArr[j]))
		}
		UtArr = append(UtArr, Uti)
	}
	// c = HashLinear
	c := HashLinear(UtArr, uArr)
	for i := 0; i < n; i++ {
		zi := ffmath.AddMod(xtArr[i], ffmath.MultiplyMod(c, xArr[i], ORDER), ORDER)
		zArr = append(zArr, zi)
	}
	return zArr, UtArr
}

func Verify(zArr []*big.Int, gArr, uArr, UtArr []*bn256.G1Affine) bool {
	n := len(zArr)
	m := len(uArr)
	// cal c
	c := HashLinear(UtArr, uArr)
	for i := 0; i < m; i++ {
		var l, r *bn256.G1Affine
		for j := 0; j < n; j++ {
			if j == 0 {
				l = new(bn256.G1Affine).ScalarMultiplication(gArr[i*n+j], zArr[j])
				continue
			}
			l = bn128.G1AffineMul(l, new(bn256.G1Affine).ScalarMultiplication(gArr[i*n+j], zArr[j]))
		}
		r = bn128.G1AffineMul(UtArr[i], new(bn256.G1Affine).ScalarMultiplication(uArr[i], c))
		if !l.Equal(r) {
			return false
		}
	}
	return true
}
