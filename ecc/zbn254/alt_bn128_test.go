package zbn254

import (
	"fmt"
	"math/big"
	"testing"
)

func TestG1Neg(t *testing.T) {
	a := big.NewInt(100)
	A := G1ScalarBaseMul(a)
	ANeg := G1Neg(A)
	C := G1Add(A, ANeg)
	fmt.Println(C)
}
