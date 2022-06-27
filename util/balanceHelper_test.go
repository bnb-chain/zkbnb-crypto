package util

import (
	"fmt"
	"math/big"
	"testing"
)

func TestToPackedAmount(t *testing.T) {
	a, _ := new(big.Int).SetString("343597383671", 10)
	amount, err := ToPackedAmount(a)
	if err != nil {
		panic(err)
	}
	fmt.Println(amount)
}
