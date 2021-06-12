package std

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type WithdrawProofConstraints struct {
	// commitments
	Pt                                  Point
	A_CLStar, A_pk, A_TDivCRprime, A_Pt Point
	// response
	Z_r, Z_rbar, Z_sk, Z_skInv Variable
	// Commitment Range Proofs
	CRangeProofs [2]ComRangeProofConstraints
	// common inputs
	C, CStar                           ElGamalEncConstraints
	H, Ht, TDivCRprime, CLprimeInv, Pk Point
	Challenge                          Variable
}

func (circuit *WithdrawProofConstraints) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	verifyWithdrawProof(cs, *circuit, params)

	return nil
}

func verifyWithdrawProof(
	cs *frontend.ConstraintSystem,
	proof WithdrawProofConstraints,
	params twistededwards.EdCurve,
) {
	// verify range proof first
	for _, rangeProof := range proof.CRangeProofs {
		verifyComRangeProof(cs, rangeProof, params)
	}

	// verify Ht
	verifyPt(cs, proof.Ht, proof.Pt, proof.A_Pt, proof.Challenge, proof.Z_sk, params)
	// verify half enc
	verifyHalfEnc(cs, proof.Pk, proof.CStar.CL, proof.A_CLStar, proof.Challenge, proof.Z_r, params)
	// verify balance
	verifyBalance(cs, proof.Pk, proof.A_pk, proof.CLprimeInv,
		proof.TDivCRprime, proof.A_TDivCRprime, proof.Challenge,
		proof.Z_sk, proof.Z_skInv, proof.Z_rbar, params)

}

func verifyPt(
	cs *frontend.ConstraintSystem,
	Ht, Pt, A_Pt Point,
	c Variable,
	z_tsk Variable,
	params twistededwards.EdCurve,
) {
	var l, r Point
	l.ScalarMulNonFixedBase(cs, &Ht, z_tsk, params)
	r.ScalarMulNonFixedBase(cs, &Pt, c, params)
	r.AddGeneric(cs, &A_Pt, &r, params)
	cs.AssertIsEqual(l.X, r.X)
	cs.AssertIsEqual(l.Y, r.Y)
}

func verifyHalfEnc(
	cs *frontend.ConstraintSystem,
	pk, CLStar, A_CLStar Point,
	c Variable,
	z_r Variable,
	params twistededwards.EdCurve,
) {
	var l, r Point
	l.ScalarMulNonFixedBase(cs, &pk, z_r, params)
	r.ScalarMulNonFixedBase(cs, &CLStar, c, params)
	r.AddGeneric(cs, &A_CLStar, &r, params)
	cs.AssertIsEqual(l.X, r.X)
	cs.AssertIsEqual(l.Y, r.Y)
}

func verifyBalance(
	cs *frontend.ConstraintSystem,
	pk, A_pk, CLprimeInv, TDivCRprime, A_TDivCRprime Point,
	c Variable,
	z_sk, z_skInv, z_rbar Variable,
	params twistededwards.EdCurve,
) {
	var l1, r1 Point
	// verify pk = g^{sk}
	l1.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_sk, params)
	r1.ScalarMulNonFixedBase(cs, &pk, c, params)
	r1.AddGeneric(cs, &A_pk, &r1, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	var g_zrbar, l2, r2 Point
	// verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	g_zrbar.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, z_rbar, params)
	l2.ScalarMulNonFixedBase(cs, &CLprimeInv, z_skInv, params)
	l2.AddGeneric(cs, &g_zrbar, &l2, params)
	r2.ScalarMulNonFixedBase(cs, &TDivCRprime, c, params)
	r2.AddGeneric(cs, &A_TDivCRprime, &r2, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
}

func setWithdrawProofWitness(proof *zecrey.WithdrawProof) (witness WithdrawProofConstraints, err error) {
	if proof == nil {
		return witness, err
	}

	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		return witness, err
	}
	if !verifyRes {
		return witness, ErrInvalidProof
	}

	// generate the challenge
	var buf bytes.Buffer
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.Ht.Marshal())
	buf.Write(proof.C.CL.Marshal())
	buf.Write(proof.C.CR.Marshal())
	buf.Write(proof.CStar.CL.Marshal())
	buf.Write(proof.CStar.CR.Marshal())
	buf.Write(proof.T.Marshal())
	buf.Write(proof.Pk.Marshal())
	buf.Write(proof.A_CLStar.Marshal())
	buf.Write(proof.A_pk.Marshal())
	buf.Write(proof.A_TDivCRprime.Marshal())

	// compute the challenge
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return witness, err
	}
	// check challenge
	if !ffmath.Equal(c, proof.Challenge) {
		return witness, ErrInvalidChallenge
	}

	witness.Challenge.Assign(c.String())

	// commitments
	witness.Pt, err = setPointWitness(proof.Pt)
	if err != nil {
		return witness, err
	}
	witness.A_CLStar, err = setPointWitness(proof.A_CLStar)
	if err != nil {
		return witness, err
	}
	witness.A_pk, err = setPointWitness(proof.A_pk)
	if err != nil {
		return witness, err
	}
	witness.A_TDivCRprime, err = setPointWitness(proof.A_TDivCRprime)
	if err != nil {
		return witness, err
	}
	witness.A_Pt, err = setPointWitness(proof.A_Pt)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_r.Assign(proof.Z_r.String())
	witness.Z_rbar.Assign(proof.Z_rbar.String())
	witness.Z_sk.Assign(proof.Z_sk.String())
	witness.Z_skInv.Assign(proof.Z_skInv.String())
	// Commitment Range Proofs
	if len(proof.CRangeProofs) != 2 {
		return witness, ErrInvalidRangeParams
	}
	witness.CRangeProofs[0], err = setComRangeProofWitness(proof.CRangeProofs[0])
	if err != nil {
		return witness, err
	}
	witness.CRangeProofs[1], err = setComRangeProofWitness(proof.CRangeProofs[1])
	if err != nil {
		return witness, err
	}
	// common inputs
	witness.C, err = setElGamalEncWitness(proof.C)
	if err != nil {
		return witness, err
	}
	witness.CStar, err = setElGamalEncWitness(proof.CStar)
	if err != nil {
		return witness, err
	}
	witness.H, err = setPointWitness(proof.H)
	if err != nil {
		return witness, err
	}
	witness.Ht, err = setPointWitness(proof.Ht)
	if err != nil {
		return witness, err
	}
	witness.TDivCRprime, err = setPointWitness(proof.TDivCRprime)
	if err != nil {
		return witness, err
	}
	witness.CLprimeInv, err = setPointWitness(proof.CLprimeInv)
	if err != nil {
		return witness, err
	}
	witness.Pk, err = setPointWitness(proof.Pk)
	if err != nil {
		return witness, err
	}
	return witness, nil
}
