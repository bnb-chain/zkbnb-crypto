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

	l := Point{
		X: cs.Constant(circuit.G.X),
		Y: cs.Constant(circuit.G.Y),
	}

	l.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z, params)

	pkc := circuit.G.ScalarMulNonFixedBase(cs, &circuit.Pk, circuit.C, params)
	r := circuit.A.AddGeneric(cs, &circuit.A, pkc, params)

	cs.AssertIsEqual(l.X, r.X)
	cs.AssertIsEqual(l.Y, r.Y)

	return nil
}

type OwnershipCircuit struct {
	G Point
	YDivT, A_YDivT, H, T,
	A_T, Pk, A_pk, CLprimeInv,
	TCRprimeInv, A_TCRprimeInv Point
	C                                               Variable
	Z_rstarSubrbar, Z_rbar, Z_bprime, Z_sk, Z_skInv Variable
}

func (circuit *OwnershipCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// verify Y/T = g^{r^{\star} - \bar{r}}
	l1 := circuit.G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z_rstarSubrbar, params)
	YDivTc := circuit.G.ScalarMulNonFixedBase(cs, &circuit.YDivT, circuit.C, params)
	r1 := circuit.G.AddGeneric(cs, &circuit.A_YDivT, YDivTc, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)
	// verify T = g^{\bar{r}} H^{b'}
	gzrbar := circuit.G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z_rbar, params)
	hzbprime := circuit.G.ScalarMulNonFixedBase(cs, &circuit.H, circuit.Z_bprime, params)
	l2 := circuit.G.AddGeneric(cs, gzrbar, hzbprime, params)
	Tc := circuit.G.ScalarMulNonFixedBase(cs, &circuit.T, circuit.C, params)
	r2 := circuit.G.AddGeneric(cs, &circuit.A_T, Tc, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
	// verify Pk = g^{sk}
	l3 := circuit.G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z_sk, params)
	pkc := circuit.G.ScalarMulNonFixedBase(cs, &circuit.Pk, circuit.C, params)
	r3 := circuit.G.AddGeneric(cs, &circuit.A_pk, pkc, params)
	cs.AssertIsEqual(l3.X, r3.X)
	cs.AssertIsEqual(l3.Y, r3.Y)
	// verify T(C'_R)^{-1} = (C'_L)^{-sk^{-1}} g^{\bar{r}}
	CLprimeInv_zskInv := circuit.G.ScalarMulNonFixedBase(cs, &circuit.CLprimeInv, circuit.Z_skInv, params)
	l4 := circuit.G.AddGeneric(cs, gzrbar, CLprimeInv_zskInv, params)
	TCRprimeInv_c := circuit.G.ScalarMulNonFixedBase(cs, &circuit.TCRprimeInv, circuit.C, params)
	r4 := circuit.G.AddGeneric(cs, &circuit.A_TCRprimeInv, TCRprimeInv_c, params)
	cs.AssertIsEqual(l4.X, r4.X)
	cs.AssertIsEqual(l4.Y, r4.Y)
	return nil
}
