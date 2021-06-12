package std

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type (
	Point    = twistededwards.Point
	Variable = frontend.Variable
)

type PTransferProofConstraints struct {
	// sub proofs
	SubProofs [3]PTransferSubProofConstraints
	// commitment for \sum_{i=1}^n b_i^{\Delta}
	A_sum Point
	// A_Pt
	A_Pt Point
	// z_tsk
	Z_tsk Variable
	// Pt = (Ht)^{sk_i}
	Pt Point
	// challenges
	C      Variable
	C1, C2 Variable
	H, Ht  Point
}

type PTransferSubProofConstraints struct {
	// sigma protocol commitment values
	A_CLDelta, A_CRDelta, A_YDivCRDelta, A_YDivT, A_T, A_pk, A_TDivCPrime Point
	// respond values
	Z_r, Z_bDelta, Z_rstarSubr, Z_rstarSubrbar, Z_rbar, Z_bprime, Z_sk, Z_skInv Variable
	// range proof
	CRangeProof ComRangeProofConstraints
	// common inputs
	// original balance enc
	C ElGamalEncConstraints
	// delta balance enc
	CDelta ElGamalEncConstraints
	// new pedersen commitment for new balance
	T Point
	// new pedersen commitment for deleta balance or new balance
	Y Point
	// public key
	Pk Point
	// T (C_R + C_R^{\Delta})^{-1}
	TCRprimeInv Point
	// (C_L + C_L^{\Delta})^{-1}
	CLprimeInv Point
}

type ElGamalEncConstraints struct {
	CL Point // Pk^r
	CR Point // g^r Waste^b
}

func (circuit *PTransferProofConstraints) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	verifyPTransferProof(cs, *circuit, params)

	return nil
}

func verifyPTransferProof(
	cs *frontend.ConstraintSystem,
	circuit PTransferProofConstraints,
	params twistededwards.EdCurve,
) {
	var l1, r1 Point
	// verify Pt = Ht^{sk}
	l1.ScalarMulNonFixedBase(cs, &circuit.Ht, circuit.Z_tsk, params)
	r1.ScalarMulNonFixedBase(cs, &circuit.Pt, circuit.C, params)
	r1.AddGeneric(cs, &circuit.A_Pt, &r1, params)

	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	lSum := Point{
		X: cs.Constant("0"),
		Y: cs.Constant("1"),
	}

	// verify sub proofs
	var YDivCRDelta, YDivT, t Point
	for _, subProof := range circuit.SubProofs {
		// verify range proof
		verifyComRangeProof(cs, subProof.CRangeProof, params)
		// verify valid enc
		verifyValidEnc(
			cs,
			subProof.Pk, subProof.CDelta.CL, subProof.A_CLDelta, circuit.H, subProof.CDelta.CR, subProof.A_CRDelta,
			circuit.C,
			subProof.Z_r, subProof.Z_bDelta,
			params,
		)
		//CRNeg := circuit.G.ScalarMulNonFixedBase(cs, &subProof.CDelta.CR, inv, params)
		CRNeg := Neg(cs, subProof.CDelta.CR, params)
		YDivCRDelta.AddGeneric(cs, &subProof.Y, CRNeg, params)

		// verify delta
		verifyValidDelta(
			cs,
			YDivCRDelta, subProof.A_YDivCRDelta,
			circuit.C1,
			subProof.Z_rstarSubr,
			params,
		)

		TNeg := Neg(cs, subProof.T, params)
		YDivT.AddGeneric(cs, &subProof.Y, TNeg, params)
		// verify ownership
		verifyOwnership(
			cs,
			YDivT, subProof.A_YDivT, circuit.H, subProof.T, subProof.A_T, subProof.Pk, subProof.A_pk, subProof.CLprimeInv, subProof.TCRprimeInv, subProof.A_TDivCPrime,
			circuit.C2,
			subProof.Z_rstarSubrbar, subProof.Z_rbar, subProof.Z_bprime, subProof.Z_sk, subProof.Z_skInv,
			params,
		)
		t.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, subProof.Z_bDelta, params)
		lSum.AddGeneric(cs, &lSum, &t, params)
	}
	cs.AssertIsEqual(lSum.X, circuit.A_sum.X)
	cs.AssertIsEqual(lSum.Y, circuit.A_sum.Y)
}

func verifyValidEnc(
	cs *frontend.ConstraintSystem,
	pk, C_LDelta, A_CLDelta, h, C_RDelta, A_CRDelta Point,
	c Variable,
	z_r, z_bDelta Variable,
	params twistededwards.EdCurve,
) {
	var l1, r1 Point
	l1.ScalarMulNonFixedBase(cs, &pk, z_r, params)
	r1.ScalarMulNonFixedBase(cs, &C_LDelta, c, params)
	r1.AddGeneric(cs, &A_CLDelta, &r1, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	var gzr, l2, r2 Point
	gzr.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_r, params)
	l2.ScalarMulNonFixedBase(cs, &h, z_bDelta, params)
	l2.AddGeneric(cs, &gzr, &l2, params)
	r2.ScalarMulNonFixedBase(cs, &C_RDelta, c, params)
	r2.AddGeneric(cs, &A_CRDelta, &r2, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
}

func verifyValidDelta(
	cs *frontend.ConstraintSystem,
	YDivCRDelta, A_YDivCRDelta Point,
	c Variable,
	z_rstarSubr Variable,
	params twistededwards.EdCurve,
) {
	var l, r Point
	l.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rstarSubr, params)
	r.ScalarMulNonFixedBase(cs, &YDivCRDelta, c, params)
	r.AddGeneric(cs, &A_YDivCRDelta, &r, params)

	cs.AssertIsEqual(l.X, r.X)
	cs.AssertIsEqual(l.Y, r.Y)
}

func verifyOwnership(
	cs *frontend.ConstraintSystem,
	YDivT, A_YDivT, h, T, A_T, pk, A_pk, CLprimeInv, TCRprimeInv, A_TCRprimeInv Point,
	c Variable,
	z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv Variable,
	params twistededwards.EdCurve,
) {
	var l1, r1 Point
	// verify Y/T = g^{r^{\star} - \bar{r}}
	l1.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rstarSubrbar, params)
	r1.ScalarMulNonFixedBase(cs, &YDivT, c, params)
	r1.AddGeneric(cs, &A_YDivT, &r1, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	var gzrbar, l2, r2 Point
	// verify T = g^{\bar{r}} Waste^{b'}
	gzrbar.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rbar, params)
	l2.ScalarMulNonFixedBase(cs, &h, z_bprime, params)
	l2.AddGeneric(cs, &gzrbar, &l2, params)
	r2.ScalarMulNonFixedBase(cs, &T, c, params)
	r2.AddGeneric(cs, &A_T, &r2, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)

	var l3, r3 Point
	// verify Pk = g^{sk}
	l3.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_sk, params)
	r3.ScalarMulNonFixedBase(cs, &pk, c, params)
	r3.AddGeneric(cs, &A_pk, &r3, params)
	cs.AssertIsEqual(l3.X, r3.X)
	cs.AssertIsEqual(l3.Y, r3.Y)

	var l4, r4 Point
	// verify T(C'_R)^{-1} = (C'_L)^{-sk^{-1}} g^{\bar{r}}
	l4.ScalarMulNonFixedBase(cs, &CLprimeInv, z_skInv, params)
	l4.AddGeneric(cs, &gzrbar, &l4, params)
	r4.ScalarMulNonFixedBase(cs, &TCRprimeInv, c, params)
	r4.AddGeneric(cs, &A_TCRprimeInv, &r4, params)
	cs.AssertIsEqual(l4.X, r4.X)
	cs.AssertIsEqual(l4.Y, r4.Y)
}

func setPointWitness(point *zecrey.Point) (witness Point, err error) {
	if point == nil {
		return witness, ErrInvalidSetParams
	}
	witness.X.Assign(point.X.String())
	witness.Y.Assign(point.Y.String())
	return witness, nil
}

func setElGamalEncWitness(encVal *zecrey.ElGamalEnc) (witness ElGamalEncConstraints, err error) {
	if encVal == nil {
		return witness, ErrInvalidSetParams
	}
	witness.CL, err = setPointWitness(encVal.CL)
	if err != nil {
		return witness, err
	}
	witness.CR, err = setPointWitness(encVal.CR)
	if err != nil {
		return witness, err
	}
	return witness, nil
}

func setTransferProofWitness(proof *zecrey.PTransferProof) (witness PTransferProofConstraints, err error) {
	if proof == nil || len(proof.Pts) != 1 || len(proof.Z_tsks) != 1 || len(proof.A_Pts) != 1 {
		return witness, ErrInvalidSetParams
	}
	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		return witness, err
	}
	if !verifyRes {
		return witness, ErrInvalidProof
	}
	// A_sum
	witness.A_sum, err = setPointWitness(proof.A_sum)
	if err != nil {
		return witness, err
	}
	// A_Pt
	witness.A_Pt, err = setPointWitness(proof.A_Pts[0])
	if err != nil {
		return witness, err
	}
	// z_tsk
	witness.Z_tsk.Assign(proof.Z_tsks[0])
	// generator Waste
	witness.H, err = setPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	// Ht = h^{tid}
	witness.Ht, err = setPointWitness(proof.Ht)
	if err != nil {
		return witness, err
	}
	// Pt = Ht^{sk}
	witness.Pt, err = setPointWitness(proof.Pts[0])
	if err != nil {
		return witness, err
	}
	// C = C1 \oplus C2
	c := ffmath.Xor(proof.C1, proof.C2)
	witness.C.Assign(c)
	witness.C1.Assign(proof.C1)
	witness.C2.Assign(proof.C1)
	// set sub proofs
	// TODO check subProofs length
	for i, subProof := range proof.SubProofs {
		// define var
		var subProofWitness PTransferSubProofConstraints
		// set values
		// A_{C_L^{\Delta}}
		subProofWitness.A_CLDelta, err = setPointWitness(subProof.A_CLDelta)
		if err != nil {
			return witness, err
		}
		// A_{C_R^{\Delta}}
		subProofWitness.A_CRDelta, err = setPointWitness(subProof.A_CRDelta)
		if err != nil {
			return witness, err
		}
		// A_{Y/C_R^{\Delta}}
		subProofWitness.A_YDivCRDelta, err = setPointWitness(subProof.A_YDivCRDelta)
		if err != nil {
			return witness, err
		}
		// A_{Y/T}
		subProofWitness.A_YDivT, err = setPointWitness(subProof.A_YDivT)
		if err != nil {
			return witness, err
		}
		// A_T
		subProofWitness.A_T, err = setPointWitness(subProof.A_T)
		if err != nil {
			return witness, err
		}
		// A_{pk}
		subProofWitness.A_pk, err = setPointWitness(subProof.A_pk)
		if err != nil {
			return witness, err
		}
		// A_{T/C'}
		subProofWitness.A_TDivCPrime, err = setPointWitness(subProof.A_TDivCPrime)
		if err != nil {
			return witness, err
		}
		// Z_r
		subProofWitness.Z_r.Assign(subProof.Z_r)
		// z_{b^{\Delta}}
		subProofWitness.Z_bDelta.Assign(subProof.Z_bDelta)
		// z_{r^{\star} - r}
		subProofWitness.Z_rstarSubr.Assign(subProof.Z_rstarSubr)
		// z_{r^{\star} - \bar{r}}
		subProofWitness.Z_rstarSubrbar.Assign(subProof.Z_rstarSubrbar)
		// z_{\bar{r}}
		subProofWitness.Z_rbar.Assign(subProof.Z_rbar)
		// z_{b'}
		subProofWitness.Z_bprime.Assign(subProof.Z_bprime)
		// z_{sk}
		subProofWitness.Z_sk.Assign(subProof.Z_sk)
		// range proof
		subProofWitness.CRangeProof, err = setComRangeProofWitness(subProof.CRangeProof)
		if err != nil {
			return witness, err
		}
		// z_{sk^{-1}}
		subProofWitness.Z_skInv.Assign(subProof.Z_skInv)
		// C
		subProofWitness.C, err = setElGamalEncWitness(subProof.C)
		if err != nil {
			return witness, err
		}
		// C^{\Delta}
		subProofWitness.CDelta, err = setElGamalEncWitness(subProof.CDelta)
		if err != nil {
			return witness, err
		}
		// T
		subProofWitness.T, err = setPointWitness(subProof.T)
		if err != nil {
			return witness, err
		}
		// Y
		subProofWitness.Y, err = setPointWitness(subProof.Y)
		if err != nil {
			return witness, err
		}
		// Pk
		subProofWitness.Pk, err = setPointWitness(subProof.Pk)
		if err != nil {
			return witness, err
		}
		// T C_R'^{-1}
		subProofWitness.TCRprimeInv, err = setPointWitness(subProof.TCRprimeInv)
		// C_L'^{-1}
		subProofWitness.CLprimeInv, err = setPointWitness(subProof.CLprimeInv)
		if err != nil {
			return witness, err
		}
		// set into witness
		witness.SubProofs[i] = subProofWitness
	}
	return witness, nil
}
