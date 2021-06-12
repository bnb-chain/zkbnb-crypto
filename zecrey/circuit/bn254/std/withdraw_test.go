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

func TestWithdrawProofCircuit_Define(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness WithdrawProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// generate withdraw proof
	sk, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(b, r, pk)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	if err != nil {
		t.Fatal(err)
	}
	bStar := big.NewInt(5)
	relation, err := zecrey.NewWithdrawRelation(bEnc, pk, b, bStar, sk, 1)
	if err != nil {
		t.Fatal(err)
	}
	withdrawProof, err := zecrey.ProveWithdraw(relation)
	if err != nil {
		t.Fatal(err)
	}
	witness, err = setWithdrawProofWitness(withdrawProof)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("constraints:", r1cs.GetNbConstraints())

	assert.SolvingSucceeded(r1cs, &witness)

}
