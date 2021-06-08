package std

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
)

type (
	Point    = twistededwards.Point
	Variable = frontend.Variable
)

type PTransferProofCircuit struct {
	// sub proofs
	SubProofs []PTransferSubProofCircuit
	// TODO BP Proof
	//BPProof *AggBulletProof
	// commitment for \sum_{i=1}^n b_i^{\Delta}
	A_sum Point
	// A_Pt
	A_Pt Point
	// z_tsk
	Z_tsk Variable
	// Pt = (Ht)^{sk_i}
	Pt Point
	// challenges
	C        Variable
	C1, C2   Variable
	G, H, Ht Point
}

type PTransferSubProofCircuit struct {
	// sigma protocol commitment values
	A_CLDelta, A_CRDelta, A_YDivCRDelta, A_YDivT, A_T, A_pk, A_TDivCPrime Point
	// respond values
	z_r, z_bDelta, z_rstarSubr, z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv Variable
	// common inputs
	// original balance enc
	C ElGamalEncCircuit
	// delta balance enc
	CDelta ElGamalEncCircuit
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

type ElGamalEncCircuit struct {
	CL Point // Pk^r
	CR Point // g^r H^b
}

func (circuit *PTransferProofCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// verify Pt = Ht^{sk}
	l1 := circuit.G.ScalarMulNonFixedBase(cs, &circuit.Ht, circuit.Z_tsk, params)
	ptc := circuit.G.ScalarMulNonFixedBase(cs, &circuit.Pt, circuit.C, params)
	r1 := circuit.G.AddGeneric(cs, &circuit.A_Pt, ptc, params)

	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	var lSum Point
	lSum.X = cs.Constant("0")
	lSum.Y = cs.Constant("1")

	// verify sub proofs
	for _, subProof := range circuit.SubProofs {
		// verify valid enc
		verifyValidEnc(
			cs,
			circuit.G,
			subProof.Pk, subProof.CDelta.CL, subProof.A_CLDelta, circuit.H, subProof.CDelta.CR, subProof.A_CRDelta,
			circuit.C,
			subProof.z_r, subProof.z_bDelta,
			params,
		)
		//CRNeg := circuit.G.ScalarMulNonFixedBase(cs, &subProof.CDelta.CR, inv, params)
		CRNeg := Neg(cs, subProof.CDelta.CR, params)
		YDivCRDelta := circuit.G.AddGeneric(cs, &subProof.Y, CRNeg, params)

		// verify delta
		verifyValidDelta(
			cs,
			circuit.G,
			*YDivCRDelta, subProof.A_YDivCRDelta,
			circuit.C1,
			subProof.z_rstarSubr,
			params,
		)

		TNeg := Neg(cs, subProof.T, params)
		YDivT := circuit.G.AddGeneric(cs, &subProof.Y, TNeg, params)
		// verify ownership
		verifyOwnership(
			cs,
			circuit.G,
			*YDivT, subProof.A_YDivT, circuit.H, subProof.T, subProof.A_T, subProof.Pk, subProof.A_pk, subProof.CLprimeInv, subProof.TCRprimeInv, subProof.A_TDivCPrime,
			circuit.C2,
			subProof.z_rstarSubrbar, subProof.z_rbar, subProof.z_bprime, subProof.z_sk, subProof.z_skInv,
			params,
		)
		t := circuit.G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, subProof.z_bDelta, params)
		lSum = *circuit.G.AddGeneric(cs, &lSum, t, params)
	}
	cs.AssertIsEqual(lSum.X, circuit.A_sum.X)
	cs.AssertIsEqual(lSum.Y, circuit.A_sum.Y)

	return nil
}

func verifyValidEnc(
	cs *frontend.ConstraintSystem,
	G Point,
	pk, C_LDelta, A_CLDelta, h, C_RDelta, A_CRDelta Point,
	c Variable,
	z_r, z_bDelta Variable,
	params twistededwards.EdCurve,
) {
	l1 := G.ScalarMulNonFixedBase(cs, &pk, z_r, params)
	CLc := G.ScalarMulNonFixedBase(cs, &C_LDelta, c, params)
	r1 := G.AddGeneric(cs, &A_CLDelta, CLc, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	gzr := G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_r, params)
	hzb := G.ScalarMulNonFixedBase(cs, &h, z_bDelta, params)
	l2 := G.AddGeneric(cs, gzr, hzb, params)
	CRc := G.ScalarMulNonFixedBase(cs, &C_RDelta, c, params)
	r2 := G.AddGeneric(cs, &A_CRDelta, CRc, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
}

func verifyValidDelta(
	cs *frontend.ConstraintSystem,
	G Point,
	YDivCRDelta, A_YDivCRDelta Point,
	c Variable,
	z_rstarSubr Variable,
	params twistededwards.EdCurve,
) {
	l := G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rstarSubr, params)
	tmp := G.ScalarMulNonFixedBase(cs, &YDivCRDelta, c, params)
	r := G.AddGeneric(cs, &A_YDivCRDelta, tmp, params)

	cs.AssertIsEqual(l.X, r.X)
	cs.AssertIsEqual(l.Y, r.Y)
}

func verifyOwnership(
	cs *frontend.ConstraintSystem,
	G Point,
	YDivT, A_YDivT, h, T, A_T, pk, A_pk, CLprimeInv, TCRprimeInv, A_TCRprimeInv Point,
	c Variable,
	z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv Variable,
	params twistededwards.EdCurve,
) {
	// verify Y/T = g^{r^{\star} - \bar{r}}
	l1 := G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rstarSubrbar, params)
	YDivTc := G.ScalarMulNonFixedBase(cs, &YDivT, c, params)
	r1 := G.AddGeneric(cs, &A_YDivT, YDivTc, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)
	// verify T = g^{\bar{r}} H^{b'}
	gzrbar := G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rbar, params)
	hzbprime := G.ScalarMulNonFixedBase(cs, &h, z_bprime, params)
	l2 := G.AddGeneric(cs, gzrbar, hzbprime, params)
	Tc := G.ScalarMulNonFixedBase(cs, &T, c, params)
	r2 := G.AddGeneric(cs, &A_T, Tc, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
	// verify Pk = g^{sk}
	l3 := G.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_sk, params)
	pkc := G.ScalarMulNonFixedBase(cs, &pk, c, params)
	r3 := G.AddGeneric(cs, &A_pk, pkc, params)
	cs.AssertIsEqual(l3.X, r3.X)
	cs.AssertIsEqual(l3.Y, r3.Y)
	// verify T(C'_R)^{-1} = (C'_L)^{-sk^{-1}} g^{\bar{r}}
	CLprimeInv_zskInv := G.ScalarMulNonFixedBase(cs, &CLprimeInv, z_skInv, params)
	l4 := G.AddGeneric(cs, gzrbar, CLprimeInv_zskInv, params)
	TCRprimeInv_c := G.ScalarMulNonFixedBase(cs, &TCRprimeInv, c, params)
	r4 := G.AddGeneric(cs, &A_TCRprimeInv, TCRprimeInv_c, params)
	cs.AssertIsEqual(l4.X, r4.X)
	cs.AssertIsEqual(l4.Y, r4.Y)
}
