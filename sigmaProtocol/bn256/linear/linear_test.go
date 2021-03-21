package linear

import (
	"ZKSneak-crypto/ecc/zbn256"
	"github.com/consensys/gurvy/bn256"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	// n = 2 , m = 1
	inf := zbn256.GetG1InfinityPoint()
	b1 := new(big.Int).SetUint64(6)
	b2 := new(big.Int).SetInt64(-6)
	g := zbn256.G1BaseAffine()
	xArr := []*big.Int{b1, b2}
	gArr := []*bn256.G1Affine{g, g}
	uArr := []*bn256.G1Affine{inf}
	zArr, UtArr := Prove(xArr, gArr, uArr)
	res := Verify(zArr, gArr, uArr, UtArr)
	assert.True(t, res, "should be true")
}
