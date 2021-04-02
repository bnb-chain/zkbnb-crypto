package bulletProofs

import (
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/elgamal/secp256k1/twistedElgamal"
	"fmt"
	"math/big"
	"testing"
)

func TestProveAggregationAndVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := zp256.RandomValue()
	b2 := big.NewInt(3)
	r2 := zp256.RandomValue()
	b1Enc := twistedElgamal.Enc(b1, r1, pk)
	b2Enc := twistedElgamal.Enc(b2, r2, pk)
	secrets := []*big.Int{b1, b2}
	gammas := []*big.Int{r1, r2}
	Vs := []*P256{b1Enc.CR, b2Enc.CR}
	params, err := Setup(32, 10)
	if err != nil {
		panic(err)
	}
	proof, err := ProveAggregation(secrets, gammas, Vs, params)
	if err != nil {
		panic(err)
	}
	res, err := proof.Verify()
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}
