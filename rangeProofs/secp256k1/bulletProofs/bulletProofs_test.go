package bulletProofs

import (
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/elgamal/secp256k1/twistedElgamal"
	"fmt"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := zp256.RandomValue()
	bEnc := twistedElgamal.Enc(b, r, pk)
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
}
