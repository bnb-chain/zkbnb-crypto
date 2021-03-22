package linear

import (
	"ZKSneak-crypto/ecc/zp256"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	// n = 2 , m = 1
	inf := zp256.InfinityPoint()
	b1 := new(big.Int).SetUint64(6)
	b2 := new(big.Int).SetInt64(-6)
	g := zp256.Base()
	xArr := []*big.Int{b1, b2}
	gArr := []*P256{g, g}
	uArr := []*P256{inf}
	zArr, UtArr := Prove(xArr, gArr, uArr)
	res := Verify(zArr, gArr, uArr, UtArr)
	assert.True(t, res, "should be true")
}
