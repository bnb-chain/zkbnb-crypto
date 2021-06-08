package std

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
)

type NegCircuit struct {
	G    Point
	P, N Point
}

func (circuit *NegCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	PNeg := Neg(cs, circuit.P, params)
	cs.AssertIsEqual(PNeg.X, circuit.N.X)
	cs.AssertIsEqual(PNeg.Y, circuit.N.Y)
	return nil
}

func Neg(cs *frontend.ConstraintSystem, p Point, params twistededwards.EdCurve) *Point {
	res := &Point{
		cs.Constant(0),
		cs.Constant(1),
	}
	// f_r
	r := cs.Constant("21888242871839275222246405745257275088548364400416034343698204186575808495617")

	xNeg := cs.Sub(r, p.X)
	res.X = xNeg
	res.Y = p.Y
	return res
}
