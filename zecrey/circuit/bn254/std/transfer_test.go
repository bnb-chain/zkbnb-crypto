package std

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestVerifyPTransferProofCircuit(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness PTransferProofCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// generate transfer proof
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
		t.Fatal(err)
	}
	relation, err := zecrey.NewPTransferProofRelation(1)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b1Enc, pk1, b1, big.NewInt(-4), sk1)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b2Enc, pk2, nil, big.NewInt(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b3Enc, pk3, nil, big.NewInt(3), nil)
	if err != nil {
		t.Fatal(err)
	}
	//err = relation.AddStatement(b4Enc, pk4, nil, big.NewInt(1), nil)
	//if err != nil {
	//	panic(err)
	//}
	transferProof, err := zecrey.ProvePTransfer(relation)
	if err != nil {
		t.Fatal(err)
	}
	witness, err = setTransferProofWitness(transferProof)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())

	assert.ProverSucceeded(r1cs, &witness)

	assert.SolvingSucceeded(r1cs, &witness)

}
