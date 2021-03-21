package bp_bn128

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"errors"
	"fmt"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"math"
	"math/big"
	"strconv"
)

/*
SetupInnerProduct is responsible for computing the common parameters.
Only works for ranges to 0 to 2^n, where n is a power of 2 and n <= 32
*/
func Setup(b int64) (BulletProofSetupParams, error) {
	if !IsPowerOfTwo(b) {
		return BulletProofSetupParams{}, errors.New("range end is not a power of 2")
	}

	params := BulletProofSetupParams{}
	params.H, params.G = zbn256.GetG1TwoBaseAffine()
	params.N = int64(math.Log2(float64(b)))
	if !IsPowerOfTwo(params.N) {
		return BulletProofSetupParams{}, fmt.Errorf("range end is a power of 2, but it's exponent should also be. Exponent: %d", params.N)
	}
	if params.N > 32 {
		return BulletProofSetupParams{}, errors.New("range end can not be greater than 2**32")
	}
	params.Gg = make([]*bn256.G1Affine, params.N)
	params.Hh = make([]*bn256.G1Affine, params.N)
	for i := int64(0); i < params.N; i++ {
		params.Gg[i], _ = zbn256.HashToG1(SEEDH + "g" + strconv.FormatInt(i, 10))
		params.Hh[i], _ = zbn256.HashToG1(SEEDH + "h" + strconv.FormatInt(i, 10))
	}
	return params, nil
}

/*
Prove computes the ZK rangeproof. The documentation and comments are based on
eprint version of Bulletproofs papers:
https://eprint.iacr.org/2017/1066.pdf
*/
func Prove(secret *fr.Element, gamma *fr.Element, V *bn256.G1Affine, params BulletProofSetupParams) (BulletProof, error) {
	var (
		proof BulletProof
	)

	// aL, aR and commitment: (A, alpha)
	aL, _ := Decompose(secret, 2, params.N)                                    // (41)
	aR, _ := computeAR(aL)                                                     // (42)
	alpha, _ := new(fr.Element).SetRandom()                                    // (43)
	A := commitVector(aL, aR, alpha, params.H, params.Gg, params.Hh, params.N) // (44)

	// sL, sR and commitment: (S, rho)                                     // (45)
	sL := sampleRandomVector(params.N)
	sR := sampleRandomVector(params.N)
	rho, _ := new(fr.Element).SetRandom()                                       // (46)
	S := commitVectorBig(sL, sR, rho, params.H, params.Gg, params.Hh, params.N) // (47)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to    (49)
	y, z, _ := HashBP(A, S)

	// ////////////////////////////////////////////////////////////////////////////
	// Second phase: page 20
	// ////////////////////////////////////////////////////////////////////////////
	tau1, _ := new(fr.Element).SetRandom() // (52)
	tau2, _ := new(fr.Element).SetRandom() // (52)

	/*
	   The paper does not describe how to compute t1 and t2.
	*/
	// compute t1: < aL - z.1^n, y^n . sR > + < sL, y^n . (aR + z . 1^n) >
	vz, _ := VectorCopy(z, params.N)
	vy := powerOf(y, params.N)

	// aL - z.1^n
	naL, _ := VectorConvertToBig(aL, params.N)
	aLmvz, _ := VectorSub(naL, vz)

	// y^n .sR
	ynsR, _ := VectorMul(vy, sR)

	// scalar prod: < aL - z.1^n, y^n . sR >
	sp1, _ := ScalarProduct(aLmvz, ynsR)

	// scalar prod: < sL, y^n . (aR + z . 1^n) >
	naR, _ := VectorConvertToBig(aR, params.N)
	aRzn, _ := VectorAdd(naR, vz)
	ynaRzn, _ := VectorMul(vy, aRzn)

	// Add z^2.2^n to the result
	// z^2 . 2^n
	p2n := powerOf(new(fr.Element).SetUint64(2), params.N)
	zsquared := ffmath.Multiply(z, z)
	z22n, _ := VectorScalarMul(p2n, zsquared)
	ynaRzn, _ = VectorAdd(ynaRzn, z22n)
	sp2, _ := ScalarProduct(sL, ynaRzn)

	// sp1 + sp2
	t1 := ffmath.Add(sp1, sp2)

	// compute t2: < sL, y^n . sR >
	t2, _ := ScalarProduct(sL, ynsR)

	// compute T1
	T1, _ := CommitG1(t1, tau1, params.H) // (53)

	// compute T2
	T2, _ := CommitG1(t2, tau2, params.H) // (53)

	// Fiat-Shamir heuristic to compute 'random' challenge x
	x, _, _ := HashBP(T1, T2)

	// ////////////////////////////////////////////////////////////////////////////
	// Third phase                                                              //
	// ////////////////////////////////////////////////////////////////////////////

	// compute bl                                                          // (58)
	sLx, _ := VectorScalarMul(sL, x)
	bl, _ := VectorAdd(aLmvz, sLx)

	// compute br                                                          // (59)
	// y^n . ( aR + z.1^n + sR.x )
	sRx, _ := VectorScalarMul(sR, x)
	aRzn, _ = VectorAdd(aRzn, sRx)
	ynaRzn, _ = VectorMul(vy, aRzn)
	// y^n . ( aR + z.1^n sR.x ) + z^2 . 2^n
	br, _ := VectorAdd(ynaRzn, z22n)

	// Compute t` = < bl, br >                                             // (60)
	tprime, _ := ScalarProduct(bl, br)

	// Compute taux = tau2 . x^2 + tau1 . x + z^2 . gamma                  // (61)
	taux := ffmath.Multiply(tau2, ffmath.Multiply(x, x))
	taux = ffmath.Add(taux, ffmath.Multiply(tau1, x))
	taux = ffmath.Add(taux, ffmath.Multiply(ffmath.Multiply(z, z), gamma))

	// Compute mu = alpha + rho.x                                          // (62)
	mu := ffmath.Multiply(rho, x)
	mu = ffmath.Add(mu, alpha)

	// Inner Product over (g, h', P.h^-mu, tprime)
	hprime := updateGenerators(params.Hh, y, params.N)

	// SetupInnerProduct Inner Product (Section 4.2)
	var setupErr error
	params.InnerProductParams, setupErr = setupInnerProduct(params.H, params.Gg, hprime, tprime, params.N)
	if setupErr != nil {
		return proof, setupErr
	}
	commit := commitInnerProduct(params.Gg, hprime, bl, br)
	proofip, _ := proveInnerProduct(bl, br, commit, params.InnerProductParams)

	proof.V = V
	proof.A = A
	proof.S = S
	proof.T1 = T1
	proof.T2 = T2
	proof.Taux = taux
	proof.Mu = mu
	proof.Tprime = tprime
	proof.InnerProductProof = proofip
	proof.Commit = commit
	proof.Params = params

	return proof, nil
}

/*
Verify returns true if and only if the proof is valid.
*/
func (proof *BulletProof) Verify() (bool, error) {
	params := proof.Params
	// Recover x, y, z using Fiat-Shamir heuristic
	x, _, _ := HashBP(proof.T1, proof.T2)
	y, z, _ := HashBP(proof.A, proof.S)

	// Switch generators                                                   // (64)
	hprime := updateGenerators(params.Hh, y, params.N)

	// ////////////////////////////////////////////////////////////////////////////
	// Check that tprime  = t(x) = t0 + t1x + t2x^2  ----------  Condition (65) //
	// ////////////////////////////////////////////////////////////////////////////

	// Compute left hand side
	lhs, _ := CommitG1(proof.Tprime, proof.Taux, params.H)

	// Compute right hand side
	z2 := ffmath.Multiply(z, z)
	x2 := ffmath.Multiply(x, x)

	rhs := zbn256.G1ScalarMult(proof.V, z2)

	delta := params.delta(y, z)

	gdelta := zbn256.G1ScalarHBaseMult(delta)
	rhs = zbn256.G1Add(rhs, gdelta)

	T1x := zbn256.G1ScalarMult(proof.T1, x)
	T2x2 := zbn256.G1ScalarMult(proof.T2, x2)

	rhs = zbn256.G1Add(rhs, T1x)
	rhs = zbn256.G1Add(rhs, T2x2)

	// Subtract lhs and rhs and compare with poitn at infinity
	c65 := rhs.Equal(lhs) // Condition (65), page 20, from eprint version

	// Compute P - lhs  #################### Condition (66) ######################

	// S^x
	Sx := zbn256.G1ScalarMult(proof.S, x)
	// A.S^x
	ASx := zbn256.G1Add(proof.A, Sx)

	// g^-z
	mz := ffmath.Sub(ORDER, z)
	vmz, _ := VectorCopy(mz, params.N)
	gpmz, _ := VectorExp(params.Gg, vmz)

	// z.y^n
	vz, _ := VectorCopy(z, params.N)
	vy := powerOf(y, params.N)
	zyn, _ := VectorMul(vy, vz)

	p2n := powerOf(new(fr.Element).SetUint64(2), params.N)
	zsquared := ffmath.Multiply(z, z)
	z22n, _ := VectorScalarMul(p2n, zsquared)

	// z.y^n + z^2.2^n
	zynz22n, _ := VectorAdd(zyn, z22n)

	lP := zbn256.G1Add(ASx, gpmz)

	// h'^(z.y^n + z^2.2^n)
	hprimeexp, _ := VectorExp(hprime, zynz22n)

	lP = zbn256.G1Add(lP, hprimeexp)

	// Compute P - rhs  #################### Condition (67) ######################

	// h^mu
	rP := zbn256.G1ScalarMult(params.H, proof.Mu)
	rP = zbn256.G1Add(rP, proof.Commit)

	// Subtract lhs and rhs and compare with poitn at infinity
	c67 := rP.Equal(lP)

	// Verify Inner Product Proof ################################################
	ok, _ := proof.InnerProductProof.Verify()

	result := c65 && c67 && ok

	return result, nil
}

/*
SampleRandomVector generates a vector composed by random big numbers.
*/
func sampleRandomVector(N int64) []*fr.Element {
	s := make([]*fr.Element, N)
	for i := int64(0); i < N; i++ {
		s[i], _ = new(fr.Element).SetRandom()
	}
	return s
}

/*
updateGenerators is responsible for computing generators in the following format:
[h_1, h_2^(y^-1), ..., h_n^(y^(-n+1))], where [h_1, h_2, ..., h_n] is the original
vector of generators. This method is used both by prover and verifier. After this
update we have that A is a vector commitments to (aL, aR . y^n). Also S is a vector
commitment to (sL, sR . y^n).
*/
func updateGenerators(Hh []*bn256.G1Affine, y *fr.Element, N int64) []*bn256.G1Affine {
	var (
		i int64
	)
	// Compute h'                                                          // (64)
	hprime := make([]*bn256.G1Affine, N)
	// Switch generators
	yinv := ffmath.Inverse(y)
	expy := yinv
	hprime[0] = Hh[0]
	i = 1
	for i < N {
		hprime[i] = zbn256.G1ScalarMult(Hh[i], expy)
		expy = ffmath.Multiply(expy, yinv)
		i = i + 1
	}
	return hprime
}

/*
aR = aL - 1^n
*/
func computeAR(x []int64) ([]int64, error) {
	result := make([]int64, len(x))
	for i := int64(0); i < int64(len(x)); i++ {
		if x[i] == 0 {
			result[i] = -1
		} else if x[i] == 1 {
			result[i] = 0
		} else {
			return nil, errors.New("input contains non-binary element")
		}
	}
	return result, nil
}

func commitVectorBig(aL, aR []*fr.Element, alpha *fr.Element, H *bn256.G1Affine, g, h []*bn256.G1Affine, n int64) *bn256.G1Affine {
	// Compute h^alpha.vg^aL.vh^aR
	R := zbn256.G1ScalarHBaseMult(alpha)
	for i := int64(0); i < n; i++ {
		R = zbn256.G1Add(R, zbn256.G1ScalarMult(g[i], aL[i]))
		R = zbn256.G1Add(R, zbn256.G1ScalarMult(h[i], aR[i]))
	}
	return R
}

/*
Commitvector computes a commitment to the bit of the secret.
*/
func commitVector(aL, aR []int64, alpha *fr.Element, H *bn256.G1Affine, g, h []*bn256.G1Affine, n int64) *bn256.G1Affine {
	// Compute h^alpha.vg^aL.vh^aR
	R := zbn256.G1ScalarHBaseMult(alpha)
	for i := int64(0); i < n; i++ {
		gaL := zbn256.G1ScalarMult(g[i], big.NewInt(aL[i]))
		haR := zbn256.G1ScalarMult(h[i], big.NewInt(aR[i]))
		R = zbn256.G1Add(R, gaL)
		R = zbn256.G1Add(R, haR)
	}
	return R
}

/*
delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
*/
func (params *BulletProofSetupParams) delta(y, z *fr.Element) *fr.Element {
	var (
		result *fr.Element
	)
	// delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
	z2 := ffmath.Multiply(z, z)
	z3 := ffmath.Multiply(z2, z)

	// < 1^n, y^n >
	v1, _ := VectorCopy(new(fr.Element).SetUint64(1), params.N)
	vy := powerOf(y, params.N)
	sp1y, _ := ScalarProduct(v1, vy)

	// < 1^n, 2^n >
	p2n := powerOf(new(fr.Element).SetUint64(2), params.N)
	sp12, _ := ScalarProduct(v1, p2n)

	result = ffmath.Sub(z, z2)
	result = ffmath.Multiply(result, sp1y)
	result = ffmath.Sub(result, ffmath.Multiply(z3, sp12))

	return result
}
