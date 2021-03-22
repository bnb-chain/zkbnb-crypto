package zp256

import (
	"fmt"
	"math/big"
	"testing"
)

func TestAdd(t *testing.T) {
	a := big.NewInt(2)
	b := big.NewInt(3)
	c := big.NewInt(8)
	A := ScalarBaseMult(a)
	B := ScalarMult(A, b)
	C := ScalarBaseMult(c)
	AB := Add(A, B)
	fmt.Println(AB.IsOnCurve())
	fmt.Println(Equal(AB, C))
}

func TestNeg(t *testing.T) {
	a := big.NewInt(100)
	A := ScalarBaseMult(a)
	ANeg := Neg(A)
	fmt.Println(A)
	fmt.Println(ANeg)
	C := Add(A, ANeg)
	fmt.Println(C.IsZero())
}
