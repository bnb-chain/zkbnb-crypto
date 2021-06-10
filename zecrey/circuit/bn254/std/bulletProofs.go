package std

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
)

type BulletProofCircuit struct {
	Vs                [4]Point
	A                 Point
	S                 Point
	T1                Point
	T2                Point
	Taux              Variable
	Mu                Variable
	That              Variable
	InnerProductProof InnerProductProofCircuit
	Commit            Point
}

type InnerProductProofCircuit struct {
	Ls    [7]Point
	Rs    [7]Point
	U     Point
	P     Point
	G     Point
	H     Point
	A     Variable
	B     Variable
	Xs    [7]Variable
	XInvs [7]Variable
}

func verifyBulletProof(
	cs *frontend.ConstraintSystem,
	proof BulletProofCircuit,
	params twistededwards.EdCurve,
) {

}

func verifyInnerProductProof(
	cs *frontend.ConstraintSystem,
	ip InnerProductProofCircuit,
	params twistededwards.EdCurve,
) {

}
