package binary

import (
	"PrivaL-crypto/commitment/secp256k1/pedersen"
	"PrivaL-crypto/ecc/zp256"
	"fmt"
	"math/big"
	"testing"
)

func TestProveAndVerify(t *testing.T) {
	m := 0
	r := zp256.RandomValue()
	c := pedersen.Commit(big.NewInt(int64(m)), r, zp256.Base(), zp256.H)
	ca, cb, f, za, zb, err := Prove(m, r)
	if err != nil {
		panic(err)
	}
	isValid := Verify(c, ca, cb, f, za, zb)
	fmt.Println(isValid)
}
