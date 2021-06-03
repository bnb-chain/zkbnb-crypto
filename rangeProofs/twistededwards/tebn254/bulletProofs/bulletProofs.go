package bulletProofs

import (
	"math/big"
	"strconv"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
)

func Setup(N int64, M int64) (params *BulletProofSetupParams, err error) {
	if M != 1 && !IsPowerOfTwo(M) {
		return nil, ErrNotPowerOfTwo
	}
	params = &BulletProofSetupParams{
		G: curve.H,
		H: curve.G,
		N: N,
	}
	nm := N * M
	params.Gs = make([]*Point, nm)
	params.Hs = make([]*Point, nm)
	for i := int64(0); i < nm; i++ {
		params.Gs[i], _ = curve.MapToGroup(SeedH + "g" + strconv.FormatInt(i, 10))
		params.Hs[i], _ = curve.MapToGroup(SeedH + "h" + strconv.FormatInt(i, 10))
	}
	return params, nil
}

/*
Prove computes the ZK rangeproof. The documentation and comments are based on
eprint version of Bulletproofs papers:
https://eprint.iacr.org/2017/1066.pdf
*/
func Prove(secret *big.Int, gamma *big.Int, V *Point, params *BulletProofSetupParams) (proof *BulletProof, err error) {

	// aL, aR and commitment: (A, alpha)
	// a_L = toBinary(secret)
	aL, _ := Decompose(secret, 2, params.N)
	// a_R = a_L - 1^n
	aR, _ := computeAR(aL)
	// A = h^{\alpha} gs^{a_L} hs^{a_R}
	alpha := curve.RandomValue()
	A := commitVector(aL, aR, alpha, params.H, params.Gs, params.Hs, params.N)

	// sL, sR and commitment: (S, rho)
	// s_L,s_R \gets_R \mathbb{Z}_p^n
	sL := RandomVector(params.N)
	sR := RandomVector(params.N)
	// S = h^{\rho} gs^{s_L} hs^{s_R}
	rho := curve.RandomValue()
	S := computeS(sL, sR, rho, params.H, params.Gs, params.Hs)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to
	// y,z are challenges
	y, z, _ := HashBP(A, S)

	// \tau_1,\tau_2 \gets_R \mathbb{Z}_p
	tau1 := curve.RandomValue()
	tau2 := curve.RandomValue()

	// l(X) = (a_L - z \cdot 1^{n}) + s_L \cdot X
	// r(X) = y^n \circ (a_R + z \cdot 1^n + s_R \cdot X) + z^2 \cdot 2^n
	// t(x) = < l(X),r(X) > = t_0 + t_1 \cdot X + t_2 \cdot X^2
	// compute t_1: < a_L - z \cdot 1^n, y^n \cdot sR > + < s_L, y^n \cdot (a_R + z \cdot 1^n) + z^2 \cdot 2^n >
	vz, _ := VectorCopy(z, params.N)
	vy := powerOfVec(y, params.N)

	// a_L - z \cdot 1^n
	iaL, _ := ToBigIntVec(aL, params.N)
	aLvz, _ := VectorSub(iaL, vz)

	// y^n \cdot s_R
	vysR, _ := VectorMul(vy, sR)

	// scalar prod: < aL - z \cdot 1^n, y^n \cdot sR >
	sp1, _ := ScalarVecMul(aLvz, vysR)

	// scalar prod: < s_L, y^n \cdot (aR + z \cdot 1^n) + z^2 \cdot 2^n >
	iaR, _ := ToBigIntVec(aR, params.N)
	aRvz, _ := VectorAdd(iaR, vz)
	vyaRvz, _ := VectorMul(vy, aRvz)

	// s_L \cdot z^2 \cdot 2^n
	p2n := powerOfVec(big.NewInt(2), params.N)
	zsquared := ffmath.MultiplyMod(z, z, Order)
	z22n, _ := VectorScalarMul(p2n, zsquared)
	vyaRvz, _ = VectorAdd(vyaRvz, z22n)
	sp2, _ := ScalarVecMul(sL, vyaRvz)

	// t_1 = sp1 + sp2
	t1 := ffmath.AddMod(sp1, sp2, Order)

	// compute t_2: < sL, y^n \cdot s_R >
	t2, _ := ScalarVecMul(sL, vysR)

	// compute T1
	// T_1 = g^{t_1} \cdot h^{\tau_1}
	T1, _ := CommitG1(t1, tau1, params.G, params.H)

	// compute T2
	// T_2 = g^{t_2} \cdot h^{\tau_2}
	T2, _ := CommitG1(t2, tau2, params.G, params.H)

	// Fiat-Shamir heuristic to compute 'random' challenge x
	// x is the challenge
	x, _, _ := HashBP(T1, T2)

	// compute l
	// l = l(x) = a_L - z \cdot 1^n + s_L \cdot x
	sLx, _ := VectorScalarMul(sL, x)
	l, _ := VectorAdd(aLvz, sLx)

	// compute r
	// r = r(x) = y^n \circ (a_R + z \cdot 1^n + s_R \cdot x) + z^2 \cdot 2^n
	sRx, _ := VectorScalarMul(sR, x)
	aRvz, _ = VectorAdd(aRvz, sRx)
	vyaRvz, _ = VectorMul(vy, aRvz)
	r, _ := VectorAdd(vyaRvz, z22n)

	// Compute \hat{t} = < l, r >
	that, _ := ScalarVecMul(l, r)

	// Compute taux = \tau_2 \cdot x^2 + \tau_1 \cdot x + z^2 \cdot gamma
	taux := ffmath.MultiplyMod(tau2, ffmath.MultiplyMod(x, x, Order), Order)
	taux = ffmath.AddMod(taux, ffmath.MultiplyMod(tau1, x, Order), Order)
	taux = ffmath.AddMod(taux, ffmath.MultiplyMod(ffmath.MultiplyMod(z, z, Order), gamma, Order), Order)

	// Compute mu = alpha + rho \cdot x
	mu := ffmath.MultiplyMod(rho, x, Order)
	mu = ffmath.AddMod(mu, alpha, Order)

	// Inner Product over (g, h', P \cdot h^{-m \cdot u}, \hat{t})
	hprimes := updateGenerators(params.Hs, y, params.N)

	// SetupInnerProduct Inner Product (Section 4.2)
	params.InnerProductParams, err = setupInnerProduct(params.H, params.Gs, hprimes, that, params.N)
	if err != nil {
		return proof, err
	}

	// prove inner product
	P := commitInnerProduct(params.Gs, hprimes, l, r)
	proofip, _ := proveInnerProduct(l, r, P, params.InnerProductParams)

	proof = &BulletProof{
		V:                 V,
		A:                 A,
		S:                 S,
		T1:                T1,
		T2:                T2,
		Taux:              taux,
		Mu:                mu,
		That:              that,
		InnerProductProof: proofip,
		Commit:            P,
		Params:            params,
	}
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
	hprimes := updateGenerators(params.Hs, y, params.N)

	// ////////////////////////////////////////////////////////////////////////////
	// Check that tprime  = t(x) = t0 + t1x + t2x^2  ----------  Condition (65) //
	// ////////////////////////////////////////////////////////////////////////////

	// Compute left hand side
	// g^{\hat{t}} h^{\tau_x} == V^{z^2} \cdot g^{\delta(y,z)} \cdot T_1^{x} \cdot T_2^{x^2}
	lhs, _ := CommitG1(proof.That, proof.Taux, params.G, params.H)

	// Compute right hand side
	z2 := ffmath.MultiplyMod(z, z, Order)
	x2 := ffmath.MultiplyMod(x, x, Order)

	rhs := curve.ScalarMul(proof.V, z2)

	delta := delta(y, z, params.N)

	gdelta := curve.ScalarMul(params.G, delta)

	rhs.Add(rhs, gdelta)

	T1x := curve.ScalarMul(proof.T1, x)
	T2x2 := curve.ScalarMul(proof.T2, x2)

	rhs.Add(rhs, T1x)
	rhs.Add(rhs, T2x2)
	c65 := lhs.Equal(rhs)

	// Compute P - lhs  #################### Condition (66) ######################

	// P = A \cdot S^x \cdot gs^{-z} \cdot (hs')^{z \cdot y^n + z^2 \cdot 2^n}
	// S^x
	Sx := curve.ScalarMul(proof.S, x)
	// A \cdot S^x
	ASx := curve.Add(proof.A, Sx)

	// g^-z
	//mz := ffmath.ModInverse(z, Order)
	mz := ffmath.Sub(Order, z)
	vmz, _ := VectorCopy(mz, params.N)
	gpmz, _ := VectorExp(params.Gs, vmz)

	// z.y^n
	vz, _ := VectorCopy(z, params.N)
	vy := powerOfVec(y, params.N)
	zyn, _ := VectorMul(vy, vz)

	p2n := powerOfVec(big.NewInt(2), params.N)
	zsquared := ffmath.MultiplyMod(z, z, Order)
	z22n, _ := VectorScalarMul(p2n, zsquared)

	// z \cdot y^n + z^2 \cdot 2^n
	zynz22n, _ := VectorAdd(zyn, z22n)

	lP := curve.Add(ASx, gpmz)

	// h'^(z.y^n + z^2.2^n)
	hprimeexp, _ := VectorExp(hprimes, zynz22n)

	lP = curve.Add(lP, hprimeexp)

	// Compute P - rhs  #################### Condition (67) ######################

	// h^mu
	rP := curve.ScalarMul(params.H, proof.Mu)
	rP = curve.Add(rP, proof.Commit)

	c67 := lP.Equal(rP)

	// Verify Inner Product Proof ################################################
	ok, _ := proof.InnerProductProof.Verify()

	result := c65 && c67 && ok

	return result, nil
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
			return nil, ErrNonBinaryElement
		}
	}
	return result, nil
}

/*
Commitvector computes a commitment to the bit of the secret.
*/
func commitVector(aL, aR []int64, alpha *big.Int, H *Point, gs, hs []*Point, n int64) *Point {
	// Compute hs^{\alpha} \cdot gs^{a_L} \cdot hs^{a_R}
	R := curve.ScalarMul(H, alpha)
	for i := int64(0); i < n; i++ {
		gaL := curve.ScalarMul(gs[i], big.NewInt(aL[i]))
		haR := curve.ScalarMul(hs[i], big.NewInt(aR[i]))
		R.Add(R, gaL)
		R.Add(R, haR)
	}
	return R
}

// S = h^{\rho} gs^{s_L} hs^{s_R}
func computeS(sL, sR []*big.Int, rho *big.Int, h *Point, gs, hs []*Point) *Point {
	S := curve.ScalarMul(h, rho)
	for i := int64(0); i < int64(len(sL)); i++ {
		S.Add(S, curve.ScalarMul(gs[i], sL[i]))
		S.Add(S, curve.ScalarMul(hs[i], sR[i]))
	}
	return S
}
