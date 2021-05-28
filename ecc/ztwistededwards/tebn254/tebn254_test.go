package tebn254

import (
	"fmt"
	"math/big"
	"testing"
)

func TestNeg(t *testing.T) {
	a := big.NewInt(100)
	A := ScalarBaseMul(a)
	ANeg := Neg(A)
	fmt.Println(A)
	fmt.Println(ANeg)
	C := Add(A, ANeg)
	fmt.Println(C)
	fmt.Println(IsZero(C))
}

func TestMapToGroup(t *testing.T) {
	HTest, err := MapToGroup("zecreyHSeed")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(HTest)
	fmt.Println(H)
	fmt.Println(U)
}
