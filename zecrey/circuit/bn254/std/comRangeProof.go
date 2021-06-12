package std

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
	"zecrey-crypto/util"
)

type ComRangeProofConstraints struct {
	// binary proof
	Cas, Cbs     [32]Point
	Fs, Zas, Zbs [32]Variable
	// same commitment proof
	Zb, Zr, Zrprime  Variable
	A_T, A_Tprime, G Point
	// public statements
	T, Tprime Point
	As        [32]Point
	C         Variable
}

// define for range proof test
func (circuit *ComRangeProofConstraints) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	verifyComRangeProof(cs, *circuit, params)
	return nil
}

/*
	verifyComRangeProof verify the range proof
	@cs: the constraint system
	@proof: the CommitmentRangeProof
	@params: params for the curve tebn254
*/
func verifyComRangeProof(
	cs *frontend.ConstraintSystem,
	proof ComRangeProofConstraints,
	params twistededwards.EdCurve,
) {
	// T' = \prod_{i=0}^{31} (A_i)^{2^i}
	Tprime := Point{
		X: cs.Constant("0"),
		Y: cs.Constant("1"),
	}
	// use current and two, in order to compute 2^i
	current := cs.Constant("1")
	two := cs.Constant("2")
	var AiMul2i Point
	for i, Ai := range proof.As {
		// verify binary proof
		verifyBinary(cs, Ai, proof.Cas[i], proof.Cbs[i],
			proof.G, proof.Fs[i], proof.Zas[i], proof.Zbs[i], proof.C, params)
		// compute AiMul2i = A_i^{2^i}
		AiMul2i.ScalarMulNonFixedBase(cs, &Ai, current, params)
		// add to T'
		Tprime.AddGeneric(cs, &Tprime, &AiMul2i, params)
		// current = 2 * current
		current = cs.Mul(current, two)
	}
	// T' should be correct
	cs.AssertIsEqual(proof.Tprime.X, Tprime.X)
	cs.AssertIsEqual(proof.Tprime.Y, Tprime.Y)
	// verify the proof: commitment for the same value
	verifyCommitmentSameValue(cs, proof.A_T, proof.A_Tprime, proof.T,
		proof.Tprime, proof.G, proof.Zb, proof.Zr, proof.Zrprime, proof.C, params)
}

/*
	verifyBinary verify the binary proof
	@cs: the constraint system
	@A: commitment for the binary value
	@Ca,Cb: random commitments
	@g: the generator
	@f,za,zb: response values for binary proof
	@params: params for the curve tebn254
*/
func verifyBinary(
	cs *frontend.ConstraintSystem,
	A, Ca, Cb, g Point,
	f, za, zb Variable,
	c Variable,
	params twistededwards.EdCurve,
) {
	var l1, hza, r1 Point
	// A^c Ca == Com(f,za)
	l1.ScalarMulNonFixedBase(cs, &A, c, params)
	l1.AddGeneric(cs, &l1, &Ca, params)
	r1.ScalarMulNonFixedBase(cs, &g, f, params)
	hza.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, za, params)
	r1.AddGeneric(cs, &r1, &hza, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	var Acf, l2, r2 Point
	// A^{c-f} Cb == Com(0,zb)
	cf := cs.Sub(c, f)
	Acf.ScalarMulNonFixedBase(cs, &A, cf, params)
	l2.AddGeneric(cs, &Acf, &Cb, params)
	r2.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, zb, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
}

/*
	verifyCommitmentSameValue verify the same value commitment proof
	@cs: the constraint system
	@A_T,A_T': random commitments
	@T,T': two public commitments
	@g: the generator
	@zb, zr, zrprime: response values for same value commitment proof
	@params: params for the curve tebn254
*/
func verifyCommitmentSameValue(
	cs *frontend.ConstraintSystem,
	A_T, A_Tprime, T, Tprime, g Point,
	zb, zr, zrprime Variable,
	c Variable,
	params twistededwards.EdCurve,
) {
	var gzb, hzr, l1, Tc, r1 Point
	// g^{zb} h^{zr} == A_T T^c
	gzb.ScalarMulNonFixedBase(cs, &g, zb, params)
	hzr.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, zr, params)
	l1.AddGeneric(cs, &gzb, &hzr, params)
	Tc.ScalarMulNonFixedBase(cs, &T, c, params)
	r1.AddGeneric(cs, &A_T, &Tc, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)

	var l2, Tprimec, r2 Point
	// g^{zb} h^{zrprime} == A_T' T'^c
	l2.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, zrprime, params)
	l2.AddGeneric(cs, &gzb, &l2, params)
	Tprimec.ScalarMulNonFixedBase(cs, &Tprime, c, params)
	r2.AddGeneric(cs, &A_Tprime, &Tprimec, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
}

/*
	setComRangeProofWitness set witness for the range proof
	@proof: original range proofs
*/
func setComRangeProofWitness(proof *commitRange.ComRangeProof) (witness ComRangeProofConstraints, err error) {
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
	witness.G, err = setPointWitness(proof.G)
	if err != nil {
		return witness, err
	}
	var buf bytes.Buffer
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.T.Marshal())
	// compute c
	// set buf and
	// check if T' = (A_i)^{2^i}
	powerof2Vec := commitRange.PowerOfVec(big.NewInt(2), int64(len(proof.As)))
	Tprime_check := curve.ZeroPoint()
	for i, Ai := range proof.As {
		witness.As[i], err = setPointWitness(Ai)
		if err != nil {
			return witness, err
		}
		witness.Cas[i], err = setPointWitness(proof.Cas[i])
		if err != nil {
			return witness, err
		}
		witness.Cbs[i], err = setPointWitness(proof.Cbs[i])
		if err != nil {
			return witness, err
		}
		witness.Fs[i].Assign(proof.Fs[i].String())
		witness.Zas[i].Assign(proof.Zas[i].String())
		witness.Zbs[i].Assign(proof.Zbs[i].String())
		//witness.PowerOfTwoVec[i].Assign(powerof2Vec[i])

		buf.Write(Ai.Marshal())
		buf.Write(proof.Cas[i].Marshal())
		buf.Write(proof.Cbs[i].Marshal())
		Tprime_check = curve.Add(Tprime_check, curve.ScalarMul(Ai, powerof2Vec[i]))
	}
	if !Tprime_check.Equal(proof.Tprime) {
		return witness, ErrInvalidRangeParams
	}
	buf.Write(proof.A_T.Marshal())
	buf.Write(proof.A_Tprime.Marshal())
	// compute the challenge
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return witness, err
	}
	witness.Zb.Assign(proof.Zb.String())
	witness.Zr.Assign(proof.Zr.String())
	witness.Zrprime.Assign(proof.Zrprime.String())
	witness.A_T, err = setPointWitness(proof.A_T)
	if err != nil {
		return witness, err
	}
	witness.A_Tprime, err = setPointWitness(proof.A_Tprime)
	if err != nil {
		return witness, err
	}
	witness.T, err = setPointWitness(proof.T)
	if err != nil {
		return witness, err
	}
	witness.Tprime, err = setPointWitness(proof.Tprime)
	if err != nil {
		return witness, err
	}
	witness.C.Assign(c.String())
	return witness, nil
}
