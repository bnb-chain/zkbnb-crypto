package elgamal

import (
	"Zecrey-crypto/ecc/zbls377"
	"fmt"
	"math/big"
	"testing"
)

func TestDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(10)
	//b := big.NewInt(100000)
	r := zbls377.RandomValue()
	bEnc := Enc(b, r, pk)
	bDec := Dec(bEnc, sk)
	fmt.Println(bDec)
}
