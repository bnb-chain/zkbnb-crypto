package elgamal

import (
	"fmt"
	"math"
	"math/big"
	"testing"
	"zecrey-crypto/ecc/zp256"
)

func TestDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(1000)
	//b := big.NewInt(100000)
	r := zp256.RandomValue()
	max := int64(math.Pow(2, 32))
	bEnc := Enc(b, r, pk)
	bDec := Dec(bEnc, sk, max)
	fmt.Println(bDec)
}
