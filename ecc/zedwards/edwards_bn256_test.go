package zedwards

import (
	"fmt"
	"math/big"
	"testing"
)

func TestF(t *testing.T) {
	p, err := MapToGroup("test")
	if err != nil {
		panic(err)
	}
	fmt.Println(p)
}

func TestScalar(t *testing.T) {
	a := big.NewInt(2)
	b := big.NewInt(3)
	c := big.NewInt(8)
	A := ScalarBaseMult(a)
	B := ScalarMult(A, b)
	C := ScalarBaseMult(c)
	AB := Add(A, B)
	fmt.Println(AB.IsOnCurve())
	fmt.Println(AB.Equal(C))
}

func TestNeg(t *testing.T) {
	a := big.NewInt(1000)
	A := ScalarBaseMult(a)
	fmt.Println(A)
	ANeg := Neg(A)
	fmt.Println(ANeg)
	C := Add(A, ANeg)
	fmt.Println(IsInfinity(C))
}
