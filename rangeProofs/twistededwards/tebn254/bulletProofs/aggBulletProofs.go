/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package bulletProofs

import (
	"math/big"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
)

/*
Prove computes the ZK rangeproof. The documentation and comments are based on
eprint version of Bulletproofs papers:
https://eprint.iacr.org/2017/1066.pdf
*/
func ProveAggregation(secrets []*big.Int, gammas []*big.Int, Vs []*Point, params *BPSetupParams) (proof *AggBulletProof, err error) {
	// check input params if they are nil
	if secrets == nil || gammas == nil || Vs == nil || params == nil {
		return nil, ErrNilParams
	}
	// check secrets and gammas size
	if len(secrets) != len(gammas) || len(secrets) != len(Vs) {
		return nil, ErrUnequalLength
	}
	// check if the length of secrets is power of 2
	m := int64(len(secrets))
	if m != 1 && !IsPowerOfTwo(m) {
		return nil, ErrNotPowerOfTwo
	}
	nm := m * params.N
	// aL, aR and commitment: (A, alpha)
	aL, err := DecomposeVec(secrets, 2, params.N)
	if err != nil {
		return nil, err
	}
	// a_R = a_L - 1^n
	aR, err := computeAR(aL)
	if err != nil {
		return nil, err
	}
	// A = h^{\alpha} gs^{a_L} hs^{a_R}
	alpha := curve.RandomValue()
	A := commitVector(aL, aR, alpha, params.H, params.Gs, params.Hs, nm)

	// sL, sR and commitment: (S, rho)
	// s_L,s_R \gets_R \mathbb{Z}_p^n
	sL := RandomVector(nm)
	sR := RandomVector(nm)
	// S = h^{\rho} gs^{s_L} hs^{s_R}
	rho := curve.RandomValue()
	S := computeS(sL, sR, rho, params.H, params.Gs, params.Hs)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to
	// y,z are challenges
	y, z, err := HashBP(A, S)
	if err != nil {
		return nil, err
	}

	// \tau_1,\tau_2 \gets_R \mathbb{Z}_p
	tau1 := curve.RandomValue()
	tau2 := curve.RandomValue()

	// l(X) = (a_L - z \cdot 1^{nm}) + s_L \cdot X
	// r(X) = y^n \circ (a_R + z \cdot 1^{nm} + s_R \cdot X) + \sum_{j=1}^m z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n})
	// t(x) = < l(X),r(X) > = t_0 + t_1 \cdot X + t_2 \cdot X^2
	// compute t_1: < a_L - z \cdot 1^{nm}, y^n \cdot sR > + < s_L, y^n \cdot (a_R + z \cdot 1^{nm}) + \sum_{j=1}^m z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n}) >
	vz, err := VectorCopy(z, nm)
	if err != nil {
		return nil, err
	}
	vy := powerOfVec(y, nm)

	// a_L - z \cdot 1^n
	iaL, err := ToBigIntVec(aL, nm)
	if err != nil {
		return nil, err
	}
	aLvz, err := VectorSub(iaL, vz)
	if err != nil {
		return nil, err
	}

	// y^n \cdot s_R
	vysR, err := VectorMul(vy, sR)
	if err != nil {
		return nil, err
	}

	// scalar prod: < aL - z \cdot 1^n, y^n \cdot sR >
	sp1, err := ScalarVecMul(aLvz, vysR)
	if err != nil {
		return nil, err
	}

	// scalar prod: < s_L, y^n \cdot (aR + z \cdot 1^{nm}) + \sum_{j=1}^m z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n}) >
	iaR, err := ToBigIntVec(aR, nm)
	if err != nil {
		return nil, err
	}
	aRvz, err := VectorAdd(iaR, vz)
	if err != nil {
		return nil, err
	}
	vyaRvz, err := VectorMul(vy, aRvz)
	if err != nil {
		return nil, err
	}

	// compute \sum_{j=1}^{m} z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n}
	p2n := powerOfVec(big.NewInt(2), params.N)
	z1pj := new(big.Int).Set(z)
	zero := big.NewInt(0)
	rz2, err := VectorCopy(zero, nm)
	if err != nil {
		return nil, err
	}
	for j := int64(1); j <= m; j++ {
		z1pj = ffmath.MultiplyMod(z1pj, z, Order)
		v0l, err := VectorCopy(zero, (j-1)*params.N)
		v0r, err := VectorCopy(zero, (m-j)*params.N)
		if err != nil {
			return nil, err
		}
		var v020 []*big.Int
		v020 = append(v020, v0l...)
		v020 = append(v020, p2n...)
		v020 = append(v020, v0r...)
		z1pjv020, err := VectorScalarMul(v020, z1pj)
		if err != nil {
			return nil, err
		}
		rz2, err = VectorAdd(rz2, z1pjv020)
		if err != nil {
			return nil, err
		}
	}

	// < s_L, y^n \cdot (aR + z \cdot 1^{nm}) + \sum_{j=1}^m z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n}) >
	vyaRvz, err = VectorAdd(vyaRvz, rz2)
	if err != nil {
		return nil, err
	}
	sp2, err := ScalarVecMul(sL, vyaRvz)
	if err != nil {
		return nil, err
	}

	// t_1 = sp1 + sp2
	t1 := ffmath.AddMod(sp1, sp2, Order)

	// compute t_2: < sL, y^n \cdot s_R >
	t2, err := ScalarVecMul(sL, vysR)
	if err != nil {
		return nil, err
	}

	// compute T1
	// T_1 = g^{t_1} \cdot h^{\tau_1}
	T1, err := CommitG1(t1, tau1, params.G, params.H)
	if err != nil {
		return nil, err
	}

	// compute T2
	// T_2 = g^{t_2} \cdot h^{\tau_2}
	T2, err := CommitG1(t2, tau2, params.G, params.H)
	if err != nil {
		return nil, err
	}

	// Fiat-Shamir heuristic to compute 'random' challenge x
	// x is the challenge
	x, _, err := HashBP(T1, T2)
	if err != nil {
		return nil, err
	}

	// compute l
	// l = l(x) = a_L - z \cdot 1^n + s_L \cdot x
	sLx, err := VectorScalarMul(sL, x)
	if err != nil {
		return nil, err
	}
	l, err := VectorAdd(aLvz, sLx)
	if err != nil {
		return nil, err
	}

	// compute r
	// r = r(x) = y^{nm} \circ (a_R + z \cdot 1^{nm} + s_R \cdot x) + \sum_{j=1}^{m} z^{1+j} \cdot (0^{(j-1)n} || 2^n || 0^{(m-j)n})
	sRx, err := VectorScalarMul(sR, x)
	if err != nil {
		return nil, err
	}
	aRvz, err = VectorAdd(aRvz, sRx)
	if err != nil {
		return nil, err
	}
	vyaRvz, err = VectorMul(vy, aRvz)
	if err != nil {
		return nil, err
	}

	r, err := VectorAdd(vyaRvz, rz2)
	if err != nil {
		return nil, err
	}

	// Compute \hat{t} = < l, r >
	that, err := ScalarVecMul(l, r)
	if err != nil {
		return nil, err
	}

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
	P, err := commitInnerProduct(params.Gs, hprimes, l, r)
	if err != nil {
		return nil, err
	}
	proofip, err := proveInnerProduct(l, r, P, params.InnerProductParams)
	if err != nil {
		return nil, err
	}

	proof = &AggBulletProof{
		Vs:                Vs,
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
func (proof *AggBulletProof) Verify() (bool, error) {
	params := proof.Params
	m := int64(len(proof.Vs))
	if m != 1 && !IsPowerOfTwo(m) {
		return false, ErrNotPowerOfTwo
	}
	nm := m * params.N
	// Recover x, y, z using Fiat-Shamir heuristic
	x, _, err := HashBP(proof.T1, proof.T2)
	y, z, err := HashBP(proof.A, proof.S)
	if err != nil {
		return false, err
	}

	// Switch generators                                                   // (64)
	hprimes := updateGenerators(params.Hs[:nm], y, nm)

	// ////////////////////////////////////////////////////////////////////////////
	// Check that tprime  = t(x) = t0 + t1x + t2x^2  ----------  Condition (65) //
	// ////////////////////////////////////////////////////////////////////////////

	// Compute left hand side
	// g^{\hat{t}} h^{\tau_x} == Vs^{z^2 z^m} \cdot g^{\delta(y,z)} \cdot T_1^{x} \cdot T_2^{x^2}
	lhs, err := CommitG1(proof.That, proof.Taux, params.G, params.H)
	if err != nil {
		return false, err
	}

	// Compute right hand side
	z2 := ffmath.MultiplyMod(z, z, Order)
	x2 := ffmath.MultiplyMod(x, x, Order)

	// Compute Vs^{z^2 z^m}
	vzm := powerOfVec(z, m)
	z2vzm, err := VectorScalarMul(vzm, z2)
	if err != nil {
		return false, err
	}
	rhs, err := VectorExp(proof.Vs, z2vzm)
	if err != nil {
		return false, err
	}

	delta, err := aggDelta(y, z, params.N, m)
	if err != nil {
		return false, err
	}
	// g^{\delta(y,z)}
	gdelta := curve.ScalarMul(params.G, delta)

	rhs.Add(rhs, gdelta)

	T1x := curve.ScalarMul(proof.T1, x)
	T2x2 := curve.ScalarMul(proof.T2, x2)

	rhs.Add(rhs, T1x)
	rhs.Add(rhs, T2x2)
	c65 := lhs.Equal(rhs)

	// Compute P - lhs  #################### Condition (66) ######################

	// P = A \cdot S^x \cdot gs^{-z} \cdot (hs')^{z \cdot y^{nm}} \cdot \prod_{j=1}^m (hs')_{[(j-1)n: jn -1]}^{z^{j+1} 2^n}
	// S^x
	Sx := curve.ScalarMul(proof.S, x)
	// A \cdot S^x
	ASx := curve.Add(proof.A, Sx)

	// gs^{-z}
	mz := ffmath.Sub(Order, z)
	vmz, err := VectorCopy(mz, nm)
	if err != nil {
		return false, err
	}
	gpmz, err := VectorExp(params.Gs, vmz)
	if err != nil {
		return false, err
	}

	// z \cdot y^{nm}
	vz, err := VectorCopy(z, nm)
	if err != nil {
		return false, err
	}
	vy := powerOfVec(y, nm)
	zynm, err := VectorMul(vy, vz)
	if err != nil {
		return false, err
	}

	p2n := powerOfVec(big.NewInt(2), params.N)
	zjp1 := new(big.Int).Set(z)
	// \prod_{j=1}^m (hs')_{[(j-1)n: jn -1]}^{z^{j+1} 2^n}
	lP := curve.ZeroPoint()
	for j := int64(1); j <= m; j++ {
		zjp1 = ffmath.MultiplyMod(zjp1, z, Order)
		zjp12n, err := VectorScalarMul(p2n, zjp1)
		if err != nil {
			return false, err
		}
		hz, err := VectorExp(hprimes[(j-1)*params.N:j*params.N], zjp12n)
		if err != nil {
			return false, err
		}
		lP.Add(lP, hz)
	}
	lP.Add(lP, ASx)
	lP.Add(lP, gpmz)

	// h'^(z.y^{nm})
	hprimeexp, err := VectorExp(hprimes, zynm)
	if err != nil {
		return false, err
	}

	lP.Add(lP, hprimeexp)

	// Compute P - rhs  #################### Condition (67) ######################

	// h^mu
	rP := curve.ScalarMul(params.H, proof.Mu)
	rP = curve.Add(rP, proof.Commit)

	c67 := lP.Equal(rP)

	// Verify Inner Product Proof ################################################
	ok, err := proof.InnerProductProof.Verify()
	if err != nil {
		return false, err
	}
	result := c65 && c67 && ok

	return result, nil
}
