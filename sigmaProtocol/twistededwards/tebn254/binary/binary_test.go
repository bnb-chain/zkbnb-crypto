package binary

import (
	"fmt"
	"math/big"
	"testing"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

var (
	H = curve.H
)

func TestProveAndVerify(t *testing.T) {
	m := 0
	r := curve.RandomValue()
	c, _ := pedersen.Commit(big.NewInt(int64(m)), r, G, H)
	ca, cb, f, za, zb, err := Prove(m, r)
	if err != nil {
		panic(err)
	}
	isValid, _ := Verify(c, ca, cb, f, za, zb)
	fmt.Println(isValid)
}
