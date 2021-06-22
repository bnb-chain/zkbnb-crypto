package linear

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

func TestProveVerify(t *testing.T) {
	// n = 2 , m = 1
	inf := curve.ZeroPoint()
	b1 := new(big.Int).SetUint64(6)
	b2 := new(big.Int).SetInt64(-6)
	g := G
	xArr := []*big.Int{b1, b2}
	gArr := []*Point{g, g}
	uArr := []*Point{&inf}
	zArr, UtArr := Prove(xArr, gArr, uArr)
	res := Verify(zArr, gArr, uArr, UtArr)
	assert.True(t, res, "should be true")
}
