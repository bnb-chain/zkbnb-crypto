package std

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
)

type SchnorrProofConstraints struct {
	A  Point
	Pk Point
	Z  Variable
	C  Variable
}

func (circuit *SchnorrProofConstraints) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	var l, r Point

	l.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z, params)

	r.ScalarMulNonFixedBase(cs, &circuit.Pk, circuit.C, params)
	r.AddGeneric(cs, &circuit.A, &r, params)

	cs.AssertIsEqual(l.X, r.X)
	cs.AssertIsEqual(l.Y, r.Y)

	return nil
}

type OwnershipConstraints struct {
	G Point
	YDivT, A_YDivT, H, T,
	A_T, Pk, A_pk, CLprimeInv,
	TCRprimeInv, A_TCRprimeInv Point
	C                                               Variable
	Z_rstarSubrbar, Z_rbar, Z_bprime, Z_sk, Z_skInv Variable
}

func (circuit *OwnershipConstraints) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	var l1, r1 Point
	// verify Y/T = g^{r^{\star} - \bar{r}}
	l1.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z_rstarSubrbar, params)
	r1.ScalarMulNonFixedBase(cs, &circuit.YDivT, circuit.C, params)
	r1.AddGeneric(cs, &circuit.A_YDivT, &r1, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	var gzrbar, l2, r2 Point
	// verify T = g^{\bar{r}} Waste^{b'}
	gzrbar.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z_rbar, params)
	l2.ScalarMulNonFixedBase(cs, &circuit.H, circuit.Z_bprime, params)
	l2.AddGeneric(cs, &gzrbar, &l2, params)
	r2.ScalarMulNonFixedBase(cs, &circuit.T, circuit.C, params)
	r2.AddGeneric(cs, &circuit.A_T, &r2, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)

	var l3, r3 Point
	// verify Pk = g^{sk}
	l3.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.Z_sk, params)
	r3.ScalarMulNonFixedBase(cs, &circuit.Pk, circuit.C, params)
	r3.AddGeneric(cs, &circuit.A_pk, &r3, params)
	cs.AssertIsEqual(l3.X, r3.X)
	cs.AssertIsEqual(l3.Y, r3.Y)

	var l4, r4 Point
	// verify T(C'_R)^{-1} = (C'_L)^{-sk^{-1}} g^{\bar{r}}
	l4.ScalarMulNonFixedBase(cs, &circuit.CLprimeInv, circuit.Z_skInv, params)
	l4.AddGeneric(cs, &gzrbar, &l4, params)
	r4.ScalarMulNonFixedBase(cs, &circuit.TCRprimeInv, circuit.C, params)
	r4.AddGeneric(cs, &circuit.A_TCRprimeInv, &r4, params)
	cs.AssertIsEqual(l4.X, r4.X)
	cs.AssertIsEqual(l4.Y, r4.Y)
	return nil
}
