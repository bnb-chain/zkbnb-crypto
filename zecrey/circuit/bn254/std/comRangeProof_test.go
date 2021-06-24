package std

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

func TestComRangeProofCircuit_Success(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness ComRangeProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	b := big.NewInt(3)
	r := curve.RandomValue()
	g := curve.H
	h := curve.G
	T, _ := pedersen.Commit(b, r, g, h)
	proof, err := commitRange.Prove(b, r, T, g, h, 32)
	if err != nil {
		t.Fatal(err)
	}
	verify, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("res:", verify)
	witness, err = setComRangeProofWitness(proof)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("constraints:", r1cs.GetNbConstraints())

	assert.SolvingSucceeded(r1cs, &witness)

}

func TestComRangeProofCircuit_Failure(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness ComRangeProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	b := big.NewInt(-5)
	r := curve.RandomValue()
	g := curve.H
	h := curve.G
	T, _ := pedersen.Commit(b, r, g, h)
	proof, err := commitRange.Prove(b, r, g, h, T, 32)
	if err != nil {
		t.Fatal(err)
	}
	verify, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("res:", verify)
	witness, err = setComRangeProofWitness(proof)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("constraints:", r1cs.GetNbConstraints())

	assert.SolvingSucceeded(r1cs, &witness)

}
