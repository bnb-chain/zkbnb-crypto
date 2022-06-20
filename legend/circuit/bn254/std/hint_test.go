package std

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"math/big"
	"testing"
)

type HintConstraints struct {
	A Variable
	B Variable
	C Variable
}

func Keccak256(curveID ecc.ID, inputs []*big.Int, outputs []*big.Int) error {
	var buf bytes.Buffer
	for i := 0; i < len(inputs); i++ {
		buf.Write(inputs[i].FillBytes(make([]byte, 32)))
	}
	hashVal := crypto.Keccak256Hash(buf.Bytes())
	result := outputs[0]
	result.SetBytes(hashVal[:])
	return nil
}

func (circuit HintConstraints) Define(api API) error {
	hashVals, err := api.Compiler().NewHint(Keccak256, 1, circuit.A, circuit.B)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hashVals[0], circuit.C)
	return nil
}

func TestHint(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(new(big.Int).SetInt64(1).FillBytes(make([]byte, 32)))
	buf.Write(new(big.Int).SetInt64(2).FillBytes(make([]byte, 32)))
	hashVal := crypto.Keccak256Hash(buf.Bytes())
	log.Println(new(big.Int).SetBytes(hashVal.Bytes()).String())
	assert := test.NewAssert(t)
	var circuit, witness HintConstraints
	witness.A = 1
	witness.B = 2
	witness.C = hashVal.Bytes()
	assert.SolvingSucceeded(
		&circuit, &witness, test.WithBackends(backend.GROTH16),
		test.WithProverOpts(backend.WithHints(Keccak256)),
		test.WithCurves(ecc.BN254),
		test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}
