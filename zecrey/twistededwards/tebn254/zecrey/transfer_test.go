package zecrey

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestCorrectInfoProve(t *testing.T) {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	//_, pk4 := twistedElgamal.GenKeyPair()
	//b4 := big.NewInt(4)
	//r4 := curve.RandomValue()
	b1Enc, err := twistedElgamal.Enc(b1, r1, pk1)
	b2Enc, err := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, err := twistedElgamal.Enc(b3, r3, pk3)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	if err != nil {
		t.Error(err)
	}
	elapse := time.Now()
	relation, err := NewPTransferProofRelation(1)
	if err != nil {
		t.Error(err)
	}
	//fmt.Println("sk1:", sk1.String())
	//fmt.Println("pk1:", curve.ToString(pk1))
	//fmt.Println("b1Enc:", b1Enc.String())
	//fmt.Println("pk2:", curve.ToString(pk2))
	//fmt.Println("b2Enc:", b2Enc.String())
	//fmt.Println("pk3:", curve.ToString(pk3))
	//fmt.Println("b3Enc:", b3Enc.String())
	err = relation.AddStatement(b1Enc, pk1, big.NewInt(-4), sk1)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b2Enc, pk2, big.NewInt(1), nil)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b3Enc, pk3, big.NewInt(3), nil)
	if err != nil {
		t.Error(err)
	}
	//err = relation.AddStatement(b4Enc, pk4, nil, big.NewInt(1), nil)
	//if err != nil {
	//	panic(err)
	//}

	transferProof, err := ProvePTransfer(relation)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("prove time:", time.Since(elapse))
	elapse = time.Now()
	var proof *PTransferProof
	proofBytes, err := json.Marshal(transferProof)
	if err != nil {
		t.Error(err)
	}
	err = json.Unmarshal(proofBytes, &proof)
	if err != nil {
		t.Error(err)
	}
	res, err := proof.Verify()
	if err != nil {
		t.Error(err)
	}
	fmt.Println(res)
	fmt.Println("verify time:", time.Since(elapse))

}

func TestIncorrectInfoProve(t *testing.T) {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	//_, pk4 := twistedElgamal.GenKeyPair()
	//b4 := big.NewInt(4)
	//r4 := curve.RandomValue()
	b1Enc, err := twistedElgamal.Enc(b1, r1, pk1)
	b2Enc, err := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, err := twistedElgamal.Enc(b3, r3, pk3)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	if err != nil {
		t.Error(err)
	}
	relation, err := NewPTransferProofRelation(1)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b1Enc, pk1, big.NewInt(-2), sk1)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b2Enc, pk2, big.NewInt(1), nil)
	if err != nil {
		t.Error(err)
	}
	err = relation.AddStatement(b3Enc, pk3, big.NewInt(3), nil)
	if err != nil {
		t.Error(err)
	}
	//err = relation.AddStatement(b4Enc, pk4, nil, big.NewInt(1), nil)
	//if err != nil {
	//	panic(err)
	//}
	transferProof, err := ProvePTransfer(relation)
	if err != nil {
		t.Fatal(err)
	}
	res, err := transferProof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res)

}
