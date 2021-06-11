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

type ComRangeProofCircuit struct {
	// binary proof
	Cas, Cbs     [32]Point
	Fs, Zas, Zbs [32]Variable
	// same commitment proof
	Zb, Zr, Zrprime     Variable
	A_T, A_Tprime, G, H Point
	// public statements
	T, Tprime Point
	As        [32]Point
	C         Variable
}

func (circuit *ComRangeProofCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	W := Point{
		X: cs.Constant("0"),
		Y: cs.Constant("1"),
	}
	Tprime := W
	current := cs.Constant("1")
	two := cs.Constant("2")
	for i, Ai := range circuit.As {
		verifyBinary(cs, circuit.H, Ai, circuit.Cas[i], circuit.Cbs[i],
			circuit.G, circuit.Fs[i], circuit.Zas[i], circuit.Zbs[i], circuit.C, params)
		AiMul2i := W.ScalarMulNonFixedBase(cs, &Ai, current, params)
		Tprime.AddGeneric(cs, &Tprime, AiMul2i, params)
		current = cs.Mul(current, two)
	}
	verifyCommitmentSameValue(cs, circuit.H, circuit.A_T, circuit.A_Tprime, circuit.T,
		Tprime, circuit.G, circuit.Zb, circuit.Zr, circuit.Zrprime, circuit.C, params)

	return nil
}

func verifyComRangeProof(
	cs *frontend.ConstraintSystem,
	proof ComRangeProofCircuit,
	params twistededwards.EdCurve,
) {
	W := Point{
		X: cs.Constant("0"),
		Y: cs.Constant("1"),
	}
	Tprime := W
	current := cs.Constant("1")
	two := cs.Constant("2")
	for i, Ai := range proof.As {
		verifyBinary(cs, proof.H, Ai, proof.Cas[i], proof.Cbs[i],
			proof.G, proof.Fs[i], proof.Zas[i], proof.Zbs[i], proof.C, params)
		AiMul2i := W.ScalarMulNonFixedBase(cs, &Ai, current, params)
		Tprime.AddGeneric(cs, &Tprime, AiMul2i, params)
		current = cs.Mul(current, two)
	}
	verifyCommitmentSameValue(cs, proof.H, proof.A_T, proof.A_Tprime, proof.T,
		Tprime, proof.G, proof.Zb, proof.Zr, proof.Zrprime, proof.C, params)
}

func verifyBinary(
	cs *frontend.ConstraintSystem,
	W Point,
	A, Ca, Cb, g Point,
	f, za, zb Variable,
	c Variable,
	params twistededwards.EdCurve,
) {
	// A^c Ca == Com(f,za)
	Ac := W.ScalarMulNonFixedBase(cs, &A, c, params)
	l1 := W.AddGeneric(cs, Ac, &Ca, params)
	gf := W.ScalarMulNonFixedBase(cs, &g, f, params)
	hza := W.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, za, params)
	r1 := W.AddGeneric(cs, gf, hza, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)
	// A^{c-f} Cb == Com(0,zb)
	cf := cs.Sub(c, f)
	Acf := W.ScalarMulNonFixedBase(cs, &A, cf, params)
	l2 := W.AddGeneric(cs, Acf, &Cb, params)
	r2 := W.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, zb, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
}

func verifyCommitmentSameValue(
	cs *frontend.ConstraintSystem,
	W Point,
	A_T, A_Tprime, T, Tprime, g Point,
	zb, zr, zrprime Variable,
	c Variable,
	params twistededwards.EdCurve,
) {
	// g^{zb} h^{zr} == A_T T^c
	gzb := W.ScalarMulNonFixedBase(cs, &g, zb, params)
	hzr := W.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, zr, params)
	l1 := W.AddGeneric(cs, gzb, hzr, params)
	Tc := W.ScalarMulNonFixedBase(cs, &T, c, params)
	r1 := W.AddGeneric(cs, &A_T, Tc, params)
	cs.AssertIsEqual(l1.X, r1.X)
	cs.AssertIsEqual(l1.Y, r1.Y)
	// g^{zb} h^{zrprime} == A_T' T'^c
	hzrprime := W.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, zrprime, params)
	l2 := W.AddGeneric(cs, gzb, hzrprime, params)
	Tprimec := W.ScalarMulNonFixedBase(cs, &Tprime, c, params)
	r2 := W.AddGeneric(cs, &A_Tprime, Tprimec, params)
	cs.AssertIsEqual(l2.X, r2.X)
	cs.AssertIsEqual(l2.Y, r2.Y)
}

func setComRangeProofWitness(proof *commitRange.ComRangeProof) (witness ComRangeProofCircuit, err error) {
	if proof == nil {
		return witness, err
	}
	witness.G, err = setPointWitness(proof.G)
	if err != nil {
		return witness, err
	}
	witness.H, err = setPointWitness(proof.H)
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
