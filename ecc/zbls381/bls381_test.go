package zbls381

import (
	"fmt"
	"math/big"
	"testing"
)

func TestG1ScalarMult(t *testing.T) {
	a := big.NewInt(2)
	b := big.NewInt(3)
	c := big.NewInt(8)
	A := G1ScalarBaseMul(a)
	B := G1ScalarMul(A, b)
	C := G1ScalarBaseMul(c)
	AB := G1Add(A, B)
	fmt.Println(AB.IsOnCurve())
	fmt.Println(AB.Equal(C))
}

func TestG1Neg(t *testing.T) {
	a := big.NewInt(39)
	A := G1ScalarBaseMul(a)
	ANeg := G1Neg(A)
	C := G1Add(A, ANeg)
	fmt.Println(C.IsInfinity())
}
