package zbn256

import (
	"fmt"
	"math/big"
	"testing"
)

func TestG1Neg(t *testing.T) {
	a := big.NewInt(100)
	A := G1ScalarBaseMult(a)
	ANeg := G1Neg(A)
	C := G1Add(A, ANeg)
	fmt.Println(C.IsInfinity())
}
