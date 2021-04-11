package bulletProofs

import (
	"Zecrey-crypto/ecc/zp256"
	"Zecrey-crypto/ffmath"
	"math/big"
)

/*
Prove computes the ZK rangeproof. The documentation and comments are based on
eprint version of Bulletproofs papers:
https://eprint.iacr.org/2017/1066.pdf
*/
func ProveAggregation(secrets []*big.Int, gammas []*big.Int, Vs []*P256, params *BulletProofSetupParams) (proof *AggBulletProof, err error) {
	proof = new(AggBulletProof)
	m := int64(len(secrets))
	nm := m * params.N
	// aL, aR and commitment: (A, alpha)
	aL, _ := DecomposeVec(secrets, 2, params.N)
	// a_R = a_L - 1^n
	aR, _ := computeAR(aL)
	// A = h^{\alpha} gs^{a_L} hs^{a_R}
	alpha := zp256.RandomValue()
	A := commitVector(aL, aR, alpha, params.H, params.Gs, params.Hs, nm)

	// sL, sR and commitment: (S, rho)
	// s_L,s_R \gets_R \mathbb{Z}_p^n
	sL := RandomVector(nm)
	sR := RandomVector(nm)
	// S = h^{\rho} gs^{s_L} hs^{s_R}
	rho := zp256.RandomValue()
	S := computeS(sL, sR, rho, params.H, params.Gs, params.Hs)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to
	// y,z are challenges
	y, z, _ := HashBP(A, S)

	// \tau_1,\tau_2 \gets_R \mathbb{Z}_p
	tau1 := zp256.RandomValue()
	tau2 := zp256.RandomValue()

	// l(X) = (a_L - z \cdot 1^{nm}) + s_L \cdot X
	// r(X) = y^n \circ (a_R + z \cdot 1^{nm} + s_R \cdot X) + \sum_{j=1}^m z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n})
	// t(x) = < l(X),r(X) > = t_0 + t_1 \cdot X + t_2 \cdot X^2
	// compute t_1: < a_L - z \cdot 1^{nm}, y^n \cdot sR > + < s_L, y^n \cdot (a_R + z \cdot 1^{nm}) + \sum_{j=1}^m z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n}) >
	vz, _ := VectorCopy(z, nm)
	vy := powerOfVec(y, nm)

	// a_L - z \cdot 1^n
	iaL, _ := ToBigIntVec(aL, nm)
	aLvz, _ := VectorSub(iaL, vz)

	// y^n \cdot s_R
	vysR, _ := VectorMul(vy, sR)

	// scalar prod: < aL - z \cdot 1^n, y^n \cdot sR >
	sp1, _ := ScalarVecMul(aLvz, vysR)

	// scalar prod: < s_L, y^n \cdot (aR + z \cdot 1^{nm}) + \sum_{j=1}^m z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n}) >
	iaR, _ := ToBigIntVec(aR, nm)
	aRvz, _ := VectorAdd(iaR, vz)
	vyaRvz, _ := VectorMul(vy, aRvz)

	// compute \sum_{j=1}^{m} z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n}
	p2n := powerOfVec(big.NewInt(2), params.N)
	z1pj := new(big.Int).Set(z)
	zero := big.NewInt(0)
	rz2, _ := VectorCopy(zero, nm)
	for j := int64(1); j <= m; j++ {
		z1pj = ffmath.MultiplyMod(z1pj, z, Order)
		v0l, _ := VectorCopy(zero, (j-1)*params.N)
		v0r, _ := VectorCopy(zero, (m-j)*params.N)
		var v020 []*big.Int
		v020 = append(v020, v0l...)
		v020 = append(v020, p2n...)
		v020 = append(v020, v0r...)
		z1pjv020, _ := VectorScalarMul(v020, z1pj)
		rz2, _ = VectorAdd(rz2, z1pjv020)
	}

	// < s_L, y^n \cdot (aR + z \cdot 1^{nm}) + \sum_{j=1}^m z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n}) >
	vyaRvz, _ = VectorAdd(vyaRvz, rz2)
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
	// r = r(x) = y^{nm} \circ (a_R + z \cdot 1^{nm} + s_R \cdot x) + \sum_{j=1}^{m} z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n})
	sRx, _ := VectorScalarMul(sR, x)
	aRvz, _ = VectorAdd(aRvz, sRx)
	vyaRvz, _ = VectorMul(vy, aRvz)

	r, _ := VectorAdd(vyaRvz, rz2)

	// Compute \hat{t} = < l, r >
	that, _ := ScalarVecMul(l, r)

	// Compute taux = \tau_2 \cdot x^2 + \tau_1 \cdot x + \sum_{j=1}^m z^{1 + j} \cdot gamma_j
	taux := ffmath.MultiplyMod(tau2, ffmath.MultiplyMod(x, x, Order), Order)
	taux = ffmath.AddMod(taux, ffmath.MultiplyMod(tau1, x, Order), Order)
	// Compute \sum_{j=1}^m z^{1 + j} \cdot gamma_j
	tz := new(big.Int).Set(z)
	for j := int64(1); j <= m; j++ {
		tz = ffmath.MultiplyMod(tz, z, Order)
		taux = ffmath.AddMod(taux, ffmath.MultiplyMod(tz, gammas[j-1], Order), Order)
	}

	// Compute mu = alpha + rho \cdot x
	mu := ffmath.MultiplyMod(rho, x, Order)
	mu = ffmath.AddMod(mu, alpha, Order)

	// Inner Product over (g, h', P \cdot h^{-m \cdot u}, \hat{t})
	hprimes := updateGenerators(params.Hs[:nm], y, nm)

	// SetupInnerProduct Inner Product (Section 4.2)
	params.InnerProductParams, err = setupInnerProduct(params.H, params.Gs[:nm], hprimes, that, nm)
	if err != nil {
		return proof, err
	}
	// prove inner product
	P := commitInnerProduct(params.Gs, hprimes, l, r)
	proofip, _ := proveInnerProduct(l, r, P, params.InnerProductParams)

	proof.Vs = Vs
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
func (proof *AggBulletProof) Verify() (bool, error) {
	params := proof.Params
	m := int64(len(proof.Vs))
	nm := m * params.N
	// Recover x, y, z using Fiat-Shamir heuristic
	x, _, _ := HashBP(proof.T1, proof.T2)
	y, z, _ := HashBP(proof.A, proof.S)

	// Switch generators                                                   // (64)
	hprimes := updateGenerators(params.Hs, y, nm)

	// ////////////////////////////////////////////////////////////////////////////
	// Check that tprime  = t(x) = t0 + t1x + t2x^2  ----------  Condition (65) //
	// ////////////////////////////////////////////////////////////////////////////

	// Compute left hand side
	// g^{\hat{t}} h^{\tau_x} == Vs^{z^2 z^m} \cdot g^{\delta(y,z)} \cdot T_1^{x} \cdot T_2^{x^2}
	lhs, _ := CommitG1(proof.That, proof.Taux, params.G, params.H)

	// Compute right hand side
	z2 := ffmath.MultiplyMod(z, z, Order)
	x2 := ffmath.MultiplyMod(x, x, Order)

	// Compute Vs^{z^2 z^m}
	vzm := powerOfVec(z, m)
	rhs := new(P256)
	z2vzm, _ := VectorScalarMul(vzm, z2)
	rhs, _ = VectorExp(proof.Vs, z2vzm)

	delta := aggDelta(y, z, params.N, m)
	// g^{\delta(y,z)}
	gdelta := zp256.ScalarMult(params.G, delta)

	rhs.Multiply(rhs, gdelta)

	T1x := zp256.ScalarMult(proof.T1, x)
	T2x2 := zp256.ScalarMult(proof.T2, x2)

	rhs.Multiply(rhs, T1x)
	rhs.Multiply(rhs, T2x2)
	c65 := zp256.Equal(lhs, rhs)

	// Compute P - lhs  #################### Condition (66) ######################

	// P = A \cdot S^x \cdot gs^{-z} \cdot (hs')^{z \cdot y^{nm}} \cdot \prod_{j=1}^m (hs')_{[(j-1)n: jn -1]}^{z^{j+1} 2^n}
	// S^x
	Sx := zp256.ScalarMult(proof.S, x)
	// A \cdot S^x
	ASx := zp256.Add(proof.A, Sx)

	// gs^{-z}
	mz := ffmath.Sub(Order, z)
	vmz, _ := VectorCopy(mz, nm)
	gpmz, _ := VectorExp(params.Gs, vmz)

	// z \cdot y^{nm}
	vz, _ := VectorCopy(z, nm)
	vy := powerOfVec(y, nm)
	zynm, _ := VectorMul(vy, vz)

	p2n := powerOfVec(big.NewInt(2), params.N)
	zjp1 := new(big.Int).Set(z)
	// \prod_{j=1}^m (hs')_{[(j-1)n: jn -1]}^{z^{j+1} 2^n}
	lP := zp256.InfinityPoint()
	for j := int64(1); j <= m; j++ {
		zjp1 = ffmath.MultiplyMod(zjp1, z, Order)
		zjp12n, _ := VectorScalarMul(p2n, zjp1)
		hz, _ := VectorExp(hprimes[(j-1)*params.N:j*params.N], zjp12n)
		lP = zp256.Add(lP, hz)
	}
	lP.Add(lP, ASx)
	lP.Add(lP, gpmz)

	// h'^(z.y^{nm})
	hprimeexp, _ := VectorExp(hprimes, zynm)

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
