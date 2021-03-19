package elgamal

import (
	"fmt"
	"github.com/consensys/gurvy/bn256/fr"
	"testing"
)

func TestDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := new(fr.Element).SetUint64(100000)
	//b := big.NewInt(100000)
	r, _ := new(fr.Element).SetRandom()
	bEnc := Enc(b, r, pk)
	bDec := Dec(bEnc, sk)
	fmt.Println(bDec)
}
