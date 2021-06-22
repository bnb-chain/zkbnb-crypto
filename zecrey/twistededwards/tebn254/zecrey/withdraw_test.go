package zecrey

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveWithdraw(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(b, r, pk)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	if err != nil {
		t.Error(err)
	}
	bStar := big.NewInt(-2)
	relation, err := NewWithdrawRelation(bEnc, pk, bStar, sk, 1)
	if err != nil {
		t.Error(err)
	}
	withdrawProof, err := ProveWithdraw(relation)
	if err != nil {
		t.Error(err)
	}
	proofBytes, err := json.Marshal(withdrawProof)
	if err != nil {
		t.Error(err)
	}
	var proof *WithdrawProof
	err = json.Unmarshal(proofBytes, &proof)
	if err != nil {
		t.Error(err)
	}
	res, err := proof.Verify()
	if err != nil {
		t.Error(err)
	}
	fmt.Println("verify res:", res)
	if res {
		bEnc.CR.Add(bEnc.CR, relation.CRStar)
		decVal, err := twistedElgamal.Dec(bEnc, sk, 100)
		if err != nil {
			t.Error(err)
		}
		fmt.Println(decVal)
	}
}
