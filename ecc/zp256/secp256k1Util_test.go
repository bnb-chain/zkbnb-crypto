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
	A := ScalarBaseMul(a)
	B := ScalarMul(A, b)
	C := ScalarBaseMul(c)
	AB := Add(A, B)
	fmt.Println(AB.IsOnCurve())
	fmt.Println(Equal(AB, C))
	fmt.Println(ScalarBaseMul(big.NewInt(0)).IsZero())
}

func TestNeg(t *testing.T) {
	a := big.NewInt(100)
	A := ScalarBaseMul(a)
	ANeg := Neg(A)
	fmt.Println(A)
	fmt.Println(ANeg)
	C := Add(A, ANeg)
	fmt.Println(C)
	fmt.Println(C.IsZero())
}
