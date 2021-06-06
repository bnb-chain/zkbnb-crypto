package zecrey

import (
	"fmt"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveWithdraw(t *testing.T) {
	params, err := Setup(32, 4)
	if err != nil {
		t.Error(err)
	}
	sk, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(b, r, pk)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	if err != nil {
		t.Error(err)
	}
	bStar := big.NewInt(5)
	relation, err := NewWithdrawRelation(bEnc, pk, b, bStar, sk, 1)
	if err != nil {
		t.Error(err)
	}
	withdrawProof, err := ProveWithdraw(relation, params)
	if err != nil {
		t.Error(err)
	}
	res, err := withdrawProof.Verify()
	if err != nil {
		t.Error(err)
	}
	if res {
		newEnc, err := twistedElgamal.EncSub(bEnc, relation.CStar)
		if err != nil {
			t.Error(err)
		}
		decVal, err := twistedElgamal.Dec(newEnc, sk, 100)
		if err != nil {
			t.Error(err)
		}
		fmt.Println(decVal)
	}
}
