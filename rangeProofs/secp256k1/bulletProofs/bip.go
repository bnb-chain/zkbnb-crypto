package bulletProofs

import (
	"ZKSneak-crypto/ecc/zp256"
	"ZKSneak-crypto/ffmath"
	"errors"
	"math/big"
	"strconv"
)

/*
SetupInnerProduct is responsible for computing the inner product basic parameters that are common to both
ProveInnerProduct and Verify algorithms.
*/
func setupInnerProduct(H *P256, gs, hs []*P256, c *big.Int, N int64) (params *InnerProductParams, err error) {
	params = new(InnerProductParams)

	if N <= 0 {
		return nil, errors.New("N must be greater than zero")
	} else {
		params.N = N
	}
	if H == nil {
		params.H = zp256.H
	} else {
		params.H = H
	}
	if gs == nil {
		params.Gs = make([]*P256, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Gs[i], _ = zp256.MapToGroup(SeedH + "g" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Gs = gs
	}
	if hs == nil {
		params.Hs = make([]*P256, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Hs[i], _ = zp256.MapToGroup(SeedH + "h" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Hs = hs
	}
	params.C = c
	params.U = zp256.U
	params.P = zp256.InfinityPoint()

	return params, nil
}

/*
proveInnerProduct calculates the Zero Knowledge Proof for the Inner Product argument.
*/
func proveInnerProduct(a, b []*big.Int, P *P256, params *InnerProductParams) (proof *InnerProductProof, err error) {
	proof = new(InnerProductProof)

	var (
		Ls []*P256
		Rs []*P256
	)

	n := int64(len(a))
	m := int64(len(b))

	if n != m {
		return proof, errors.New("size of first array argument must be equal to the second")
	}

	// Fiat-Shamir:
	// x = Hash(gs,hs,P,c)
	x, _ := hashIP(params.Gs, params.Hs, P, params.C, params.N)
	// P' = P \cdot u^(x \cdot c)
	ux := zp256.ScalarMult(params.U, x)
	uxc := zp256.ScalarMult(ux, params.C)
	Pprime := zp256.Add(P, uxc)
	// Execute Protocol 2 recursively
	proof = computeBipRecursive(a, b, params.Gs, params.Hs, ux, Pprime, n, Ls, Rs)
	proof.Params = params
	proof.Params.P = Pprime
	return proof, nil
}

/*
computeBipRecursive is the main recursive function that will be used to compute the inner product argument.
*/
func computeBipRecursive(a, b []*big.Int, g, h []*P256, u, P *P256, n int64, Ls, Rs []*P256) *InnerProductProof {
	proof := new(InnerProductProof)

	var (
		cL, cR, x, xinv, x2, x2inv       *big.Int
		L, R, Lh, Rh, Pprime             *P256
		gprime, hprime, gprime2, hprime2 []*P256
		aprime, bprime, aprime2, bprime2 []*big.Int
	)

	if n == 1 {
		// recursion end
		proof.A = a[0]
		proof.B = b[0]
		proof.G = g[0]
		proof.H = h[0]
		proof.P = P
		proof.U = u
		proof.Ls = Ls
		proof.Rs = Rs
	} else {
		// recursion

		// nprime := n / 2
		nprime := n / 2

		// Compute cL = < a[:n'], b[n':] >
		cL, _ = ScalarVecMul(a[:nprime], b[nprime:])
		// Compute cR = < a[n':], b[:n'] >
		cR, _ = ScalarVecMul(a[nprime:], b[:nprime])
		// Compute L = g_[n':]^(a_[:n']) \cdot h_[:n']^(b_[n':]) \cdot u^{c_L}
		L, _ = VectorExp(g[nprime:], a[:nprime])
		Lh, _ = VectorExp(h[:nprime], b[nprime:])
		L.Multiply(L, Lh)
		L.Multiply(L, zp256.ScalarMult(u, cL))

		// Compute r = g_[:n']^(a_[n':]) \cdot h_[n':]^(b_[:n']) \cdot u^{c_R}
		R, _ = VectorExp(g[:nprime], a[nprime:])
		Rh, _ = VectorExp(h[nprime:], b[:nprime])
		R.Multiply(R, Rh)
		R.Multiply(R, new(P256).ScalarMult(u, cR))

		// Fiat-Shamir:
		x, _, _ = HashBP(L, R)
		xinv = ffmath.ModInverse(x, Order)

		// Compute g' = g_[:n']^(x^-1) \cdot g_[n':]^(x)
		gprime = vectorScalarExp(g[:nprime], xinv)
		gprime2 = vectorScalarExp(g[nprime:], x)
		gprime, _ = VectorECAdd(gprime, gprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		hprime = vectorScalarExp(h[:nprime], x)
		hprime2 = vectorScalarExp(h[nprime:], xinv)
		hprime, _ = VectorECAdd(hprime, hprime2)

		// Compute P' = L^(x^2).P.r^(x^-2)                                    // (31)
		x2 = ffmath.MultiplyMod(x, x, Order)
		x2inv = ffmath.ModInverse(x2, Order)
		Pprime = zp256.ScalarMult(L, x2)
		Pprime.Multiply(Pprime, P)
		Pprime.Multiply(Pprime, zp256.ScalarMult(R, x2inv))

		// Compute a' = a_[:n'] \cdot x      + a_[n':] \cdot x^(-1)                         // (33)
		aprime, _ = VectorScalarMul(a[:nprime], x)
		aprime2, _ = VectorScalarMul(a[nprime:], xinv)
		aprime, _ = VectorAdd(aprime, aprime2)
		// Compute b' = b_[:n'] \cdot x^(-1) + b_[n':] \cdot x                              // (34)
		bprime, _ = VectorScalarMul(b[:nprime], xinv)
		bprime2, _ = VectorScalarMul(b[nprime:], x)
		bprime, _ = VectorAdd(bprime, bprime2)

		Ls = append(Ls, L)
		Rs = append(Rs, R)
		// recursion computeBipRecursive(g',h',u,P'; a', b')                  // (35)
		proof = computeBipRecursive(aprime, bprime, gprime, hprime, u, Pprime, nprime, Ls, Rs)
	}
	proof.N = n
	return proof
}

/*
Verify is responsible for the verification of the Inner Product Proof.
*/
func (proof *InnerProductProof) Verify() (bool, error) {

	logn := len(proof.Ls)
	var (
		x, xinv, x2, x2inv                   *big.Int
		ngprime, nhprime, ngprime2, nhprime2 []*zp256.P256
	)

	gprime := proof.Params.Gs
	hprime := proof.Params.Hs
	Pprime := proof.Params.P
	nprime := proof.N
	for i := int64(0); i < int64(logn); i++ {
		nprime = nprime / 2                        // (20)
		x, _, _ = HashBP(proof.Ls[i], proof.Rs[i]) // (26)
		xinv = ffmath.ModInverse(x, Order)
		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		ngprime = vectorScalarExp(gprime[:nprime], xinv)
		ngprime2 = vectorScalarExp(gprime[nprime:], x)
		gprime, _ = VectorECAdd(ngprime, ngprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		nhprime = vectorScalarExp(hprime[:nprime], x)
		nhprime2 = vectorScalarExp(hprime[nprime:], xinv)
		hprime, _ = VectorECAdd(nhprime, nhprime2)
		// Compute P' = L^(x^2).P.r^(x^-2)                                    // (31)
		x2 = ffmath.MultiplyMod(x, x, Order)
		x2inv = ffmath.ModInverse(x2, Order)
		Pprime.Multiply(Pprime, zp256.ScalarMult(proof.Ls[i], x2))
		Pprime.Multiply(Pprime, zp256.ScalarMult(proof.Rs[i], x2inv))
	}

	// c == a*b and checks if P = g^a.h^b.u^c                                     // (16)
	ab := ffmath.MultiplyMod(proof.A, proof.B, Order)
	// Compute right hand side
	rhs := zp256.ScalarMult(gprime[0], proof.A)
	hb := zp256.ScalarMult(hprime[0], proof.B)
	rhs.Multiply(rhs, hb)
	rhs.Multiply(rhs, zp256.ScalarMult(proof.U, ab))
	// Compute inverse of left hand side
	//nP := Pprime.Neg(Pprime)
	//nP.Multiply(nP, rhs)
	// If both sides are equal then nP must be zero                               // (17)
	c := zp256.Equal(Pprime, rhs)

	return c, nil
}

/*
commitInnerProduct is responsible for calculating g^a.h^b.
*/
func commitInnerProduct(g, h []*P256, a, b []*big.Int) *P256 {
	vga, _ := VectorExp(g, a)
	vhb, _ := VectorExp(h, b)
	result := zp256.Add(vga, vhb)
	return result
}
