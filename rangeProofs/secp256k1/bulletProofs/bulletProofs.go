package bulletProofs

import (
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/ffmath"
	"errors"
	"math/big"
	"strconv"
)

func Setup(N int64, M int64) (params *BulletProofSetupParams, err error) {
	//if !IsPowerOfTwo(N) {
	//	return nil, errors.New("range end is not a power of 2")
	//}
	params = new(BulletProofSetupParams)
	// TODO change base for twisted_elgamal
	params.G = zp256.H
	params.H = zp256.Base()
	params.N = N
	nm := N * M
	params.Gs = make([]*P256, nm)
	params.Hs = make([]*P256, nm)
	for i := int64(0); i < nm; i++ {
		params.Gs[i], _ = zp256.MapToGroup(SeedH + "g" + strconv.FormatInt(i, 10))
		params.Hs[i], _ = zp256.MapToGroup(SeedH + "h" + strconv.FormatInt(i, 10))
	}
	return params, nil
}

/*
Prove computes the ZK rangeproof. The documentation and comments are based on
eprint version of Bulletproofs papers:
https://eprint.iacr.org/2017/1066.pdf
*/
func Prove(secret *big.Int, gamma *big.Int, V *P256, params *BulletProofSetupParams) (proof *BulletProof, err error) {
	proof = new(BulletProof)

	// aL, aR and commitment: (A, alpha)
	// a_L = toBinary(secret)
	aL, _ := Decompose(secret, 2, params.N)
	// a_R = a_L - 1^n
	aR, _ := computeAR(aL)
	// A = h^{\alpha} gs^{a_L} hs^{a_R}
	alpha := zp256.RandomValue()
	A := commitVector(aL, aR, alpha, params.H, params.Gs, params.Hs, params.N)

	// sL, sR and commitment: (S, rho)
	// s_L,s_R \gets_R \mathbb{Z}_p^n
	sL := RandomVector(params.N)
	sR := RandomVector(params.N)
	// S = h^{\rho} gs^{s_L} hs^{s_R}
	rho := zp256.RandomValue()
	S := computeS(sL, sR, rho, params.H, params.Gs, params.Hs)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to
	// y,z are challenges
	y, z, _ := HashBP(A, S)

	// \tau_1,\tau_2 \gets_R \mathbb{Z}_p
	tau1 := zp256.RandomValue()
	tau2 := zp256.RandomValue()

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

	proof.V = V
	proof.A = A
	proof.S = S
	proof.T1 = T1
	proof.T2 = T2
	proof.Taux = taux
	proof.Mu = mu
	proof.That = that
	proof.InnerProductProof = proofip
	proof.Commit = P
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

	rhs := zp256.ScalarMult(proof.V, z2)

	delta := delta(y, z, params.N)

	gdelta := zp256.ScalarMult(params.G, delta)

	rhs.Multiply(rhs, gdelta)

	T1x := zp256.ScalarMult(proof.T1, x)
	T2x2 := zp256.ScalarMult(proof.T2, x2)

	rhs.Multiply(rhs, T1x)
	rhs.Multiply(rhs, T2x2)
	c65 := zp256.Equal(lhs, rhs)

	// Compute P - lhs  #################### Condition (66) ######################

	// P = A \cdot S^x \cdot gs^{-z} \cdot (hs')^{z \cdot y^n + z^2 \cdot 2^n}
	// S^x
	Sx := zp256.ScalarMult(proof.S, x)
	// A \cdot S^x
	ASx := zp256.Add(proof.A, Sx)

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

	lP := new(P256)
	lP.Add(ASx, gpmz)

	// h'^(z.y^n + z^2.2^n)
	hprimeexp, _ := VectorExp(hprimes, zynz22n)

	lP.Add(lP, hprimeexp)

	// Compute P - rhs  #################### Condition (67) ######################

	// h^mu
	rP := zp256.ScalarMult(params.H, proof.Mu)
	rP.Multiply(rP, proof.Commit)

	c67 := zp256.Equal(lP, rP)

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
			return nil, errors.New("input contains non-binary element")
		}
	}
	return result, nil
}

/*
Commitvector computes a commitment to the bit of the secret.
*/
func commitVector(aL, aR []int64, alpha *big.Int, H *P256, g, h []*P256, n int64) *P256 {
	// Compute h^{\alpha} \cdot v \cdot g^{a_L} \cdot v \cdot h^{a_R}
	R := zp256.ScalarMult(H, alpha)
	for i := int64(0); i < n; i++ {
		gaL := zp256.ScalarMult(g[i], big.NewInt(aL[i]))
		haR := zp256.ScalarMult(h[i], big.NewInt(aR[i]))
		R.Multiply(R, gaL)
		R.Multiply(R, haR)
	}
	return R
}

func computeS(sL, sR []*big.Int, rho *big.Int, h *P256, gVec, hVec []*P256) *P256 {
	S := zp256.ScalarMult(h, rho)
	for i := int64(0); i < int64(len(sL)); i++ {
		S.Multiply(S, zp256.ScalarMult(gVec[i], sL[i]))
		S.Multiply(S, zp256.ScalarMult(hVec[i], sR[i]))
	}
	return S
}
