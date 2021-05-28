package elgamal

import (
	"zecrey-crypto/ecc/zbn254"
	"fmt"
	"math/big"
	"testing"
)

func TestDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(100000)
	//b := big.NewInt(100000)
	r := zbn254.RandomValue()
	bEnc := Enc(b, r, pk)
	bDec := Dec(bEnc, sk)
	fmt.Println(bDec)
}
