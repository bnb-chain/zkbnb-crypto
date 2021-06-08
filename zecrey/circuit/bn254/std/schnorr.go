package std

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
)

type SchnorrProofCircuit struct {
	G  Point
	A  Point
	Pk Point
	Z  Variable
	C  Variable
}

func (circuit *SchnorrProofCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	l := circuit.G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z, params)
	pkc := circuit.G.ScalarMulNonFixedBase(cs, &circuit.Pk, circuit.C, params)
	r := circuit.G.AddGeneric(cs, &circuit.A, pkc, params)

	cs.AssertIsEqual(l.X, r.X)
	cs.AssertIsEqual(l.Y, r.Y)

	return nil
}
