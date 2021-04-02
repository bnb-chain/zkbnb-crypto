package elgamal

import (
	"PrivaL-crypto/ecc/zp256"
	"fmt"
	"math/big"
	"testing"
)

func TestDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(1000000)
	//b := big.NewInt(100000)
	r := zp256.RandomValue()
	bEnc := Enc(b, r, pk)
	bDec := Dec(bEnc, sk)
	fmt.Println(bDec)
}
