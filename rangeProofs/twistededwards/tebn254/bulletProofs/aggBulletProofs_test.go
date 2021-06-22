package bulletProofs

import (
	"fmt"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveAggregationAndVerify(t *testing.T) {
	//for i := 0; i < 100; i++ {
	_, pk := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
	b2 := big.NewInt(3)
	r2 := curve.RandomValue()
	b3 := big.NewInt(8)
	r3 := curve.RandomValue()
	b4 := big.NewInt(3)
	r4 := curve.RandomValue()
	b1Enc, _ := twistedElgamal.Enc(b1, r1, pk)
	b2Enc, _ := twistedElgamal.Enc(b2, r2, pk)
	b3Enc, _ := twistedElgamal.Enc(b3, r3, pk)
	b4Enc, _ := twistedElgamal.Enc(b4, r4, pk)
	secrets := []*big.Int{b1, b2, b3, b4}
	gammas := []*big.Int{r1, r2, r3, r4}
	Vs := []*Point{b1Enc.CR, b2Enc.CR, b3Enc.CR, b4Enc.CR}
	params, err := Setup(32, 4)
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
	fmt.Println(len(proof.InnerProductProof.Ls))
	fmt.Println(res)
	//}
}
