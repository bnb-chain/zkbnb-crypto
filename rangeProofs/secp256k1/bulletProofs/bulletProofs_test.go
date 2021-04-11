package bulletProofs

import (
	"Zecrey-crypto/ecc/zp256"
	"Zecrey-crypto/elgamal/secp256k1/twistedElgamal"
	"fmt"
	"math/big"
	"testing"
)

const MAX_RANGE_END = 4294967296

func TestProveVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := zp256.RandomValue()
	bEnc := twistedElgamal.Enc(b, r, pk)
	params, err := Setup(MAX_RANGE_END)
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
