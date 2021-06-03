package bulletProofs

import (
	"fmt"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveVerify(t *testing.T) {
	//for i := 0; i < 100; i++ {
	_, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(4200000000)
	r := curve.RandomValue()
	bEnc, _ := twistedElgamal.Enc(b, r, pk)
	params, err := Setup(32, 1)
	if err != nil {
		panic(err)
	}
	proof, err := Prove(b, r, bEnc.CR, params)
	if err != nil {
		panic(err)
	}
	res, err := proof.Verify()
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
	//}
}
