package std

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

func TestNeg(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness NegCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	r := curve.RandomValue()
	P := curve.ScalarBaseMul(r)
	PNeg := curve.Neg(P)

	witness.G.X.Assign("9671717474070082183213120605117400219616337014328744928644933853176787189663")
	witness.G.Y.Assign("16950150798460657717958625567821834550301663161624707787222815936182638968203")
	witness.P.X.Assign(P.X.String())
	witness.P.Y.Assign(P.Y.String())
	witness.N.X.Assign(PNeg.X.String())
	witness.N.Y.Assign(PNeg.Y.String())

	assert.SolvingSucceeded(r1cs, &witness)

}
