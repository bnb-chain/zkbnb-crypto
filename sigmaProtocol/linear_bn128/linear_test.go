package linear_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"github.com/consensys/gurvy/bn256"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	// n = 2 , m = 1
	inf := bn128.GetG1InfinityPoint()
	b1 := big.NewInt(6)
	b2 := big.NewInt(-6)
	g := bn128.GetG1BaseAffine()
	xArr := []*big.Int{b1, b2}
	gArr := []*bn256.G1Affine{g, g}
	uArr := []*bn256.G1Affine{inf}
	zArr, UtArr := Prove(xArr, gArr, uArr)
	res := Verify(zArr, gArr, uArr, UtArr)
	assert.True(t, res, "should be true")
}
