package tebn254

import (
	"fmt"
	"math/big"
	"testing"
)

func TestNeg(t *testing.T) {
	a := big.NewInt(5)
	b := big.NewInt(-5)
	A := ScalarBaseMul(a)
	B := ScalarBaseMul(b)
	AB := Add(A, B)
	fmt.Println(A)
	fmt.Println(B)
	fmt.Println(AB)
	ANeg := Neg(A)
	ANeg2 := ScalarMul(A, big.NewInt(-1))
	fmt.Println(A)
	fmt.Println(B)
	fmt.Println(ANeg)
	fmt.Println(ANeg2)
	C := Add(A, ANeg)
	C2 := Add(A, ANeg2)
	fmt.Println(C)
	fmt.Println(C2)
	fmt.Println(IsInfinity(C))
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

func TestAdd(t *testing.T) {
	r1 := big.NewInt(3)
	r2 := big.NewInt(9)
	A1 := ScalarBaseMul(r1)
	Neutral := InfinityPoint()
	A1Copy := Add(A1, Neutral)
	fmt.Println(A1)
	fmt.Println(A1Copy)
	A2 := ScalarBaseMul(r2)
	fmt.Println(A2)
	fmt.Println(A1)
	A2 = Add(A2, A1)
	fmt.Println(A2)
	fmt.Println(A1)
}
