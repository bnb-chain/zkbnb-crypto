package zbls377

import (
	"fmt"
	"math/big"
	"testing"
)

func TestG1ScalarMult(t *testing.T) {
	a := big.NewInt(2)
	b := big.NewInt(3)
	c := big.NewInt(8)
	A := G1ScalarBaseMult(a)
	B := G1ScalarMult(A, b)
	C := G1ScalarBaseMult(c)
	AB := G1Add(A, B)
	fmt.Println(AB.IsOnCurve())
	fmt.Println(AB.Equal(C))
}

func TestG1Neg(t *testing.T) {
	a := big.NewInt(39)
	A := G1ScalarBaseMult(a)
	ANeg := G1Neg(A)
	C := G1Add(A, ANeg)
	fmt.Println(C.IsInfinity())
}
