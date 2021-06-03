package bulletProofs

import (
	"errors"
	"math/big"
	"strconv"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
)

/*
SetupInnerProduct is responsible for computing the inner product basic parameters that are common to both
ProveInnerProduct and Verify algorithms.
*/
func setupInnerProduct(H *Point, gs, hs []*Point, c *big.Int, N int64) (params *InnerProductParams, err error) {
	params = new(InnerProductParams)

	if N <= 0 {
		return nil, errors.New("N must be greater than zero")
	} else {
		params.N = N
	}
	if H == nil {
		params.H = curve.H
	} else {
		params.H = H
	}
	if gs == nil {
		params.Gs = make([]*Point, N)
		for i := int64(0); i < N; i++ {
			params.Gs[i], _ = curve.MapToGroup(SeedH + "g" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Gs = gs
	}
	if hs == nil {
		params.Hs = make([]*Point, N)
		for i := int64(0); i < N; i++ {
			params.Hs[i], _ = curve.MapToGroup(SeedH + "h" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Hs = hs
	}
	params.C = c
	params.U = curve.U
	params.P = curve.ZeroPoint()

	return params, nil
}

/*
proveInnerProduct calculates the Zero Knowledge Proof for the Inner Product argument.
*/
func proveInnerProduct(a, b []*big.Int, P *Point, params *InnerProductParams) (proof *InnerProductProof, err error) {
	proof = new(InnerProductProof)

	var (
		Ls []*Point
		Rs []*Point
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
	ux := curve.ScalarMul(params.U, x)
	uxc := curve.ScalarMul(ux, params.C)
	Pprime := curve.Add(P, uxc)
	// Execute Protocol 2 recursively
	proof = computeBipRecursive(a, b, params.Gs, params.Hs, ux, Pprime, n, Ls, Rs)
	proof.Params = params
	proof.Params.P = Pprime
	return proof, nil
}

/*
computeBipRecursive is the main recursive function that will be used to compute the inner product argument.
*/
func computeBipRecursive(a, b []*big.Int, g, h []*Point, u, P *Point, n int64, Ls, Rs []*Point) *InnerProductProof {
	proof := new(InnerProductProof)

	var (
		cL, cR, x, xinv, x2, x2inv       *big.Int
		L, R, Lh, Rh, Pprime             *Point
		gprime, hprime, gprime2, hprime2 []*Point
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
		L = curve.Add(L, Lh)
		L = curve.Add(L, curve.ScalarMul(u, cL))

		// Compute r = g_[:n']^(a_[n':]) \cdot h_[n':]^(b_[:n']) \cdot u^{c_R}
		R, _ = VectorExp(g[:nprime], a[nprime:])
		Rh, _ = VectorExp(h[nprime:], b[:nprime])
		R = curve.Add(R, Rh)
		R = curve.Add(R, curve.ScalarMul(u, cR))

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
		Pprime = curve.ScalarMul(L, x2)
		Pprime = curve.Add(Pprime, P)
		Pprime = curve.Add(Pprime, curve.ScalarMul(R, x2inv))

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
		ngprime, nhprime, ngprime2, nhprime2 []*Point
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
		Pprime = curve.Add(Pprime, curve.ScalarMul(proof.Ls[i], x2))
		Pprime = curve.Add(Pprime, curve.ScalarMul(proof.Rs[i], x2inv))
	}

	// c == a*b and checks if P = g^a.h^b.u^c                                     // (16)
	ab := ffmath.MultiplyMod(proof.A, proof.B, Order)
	// Compute right hand side
	rhs := curve.ScalarMul(gprime[0], proof.A)
	hb := curve.ScalarMul(hprime[0], proof.B)
	rhs = curve.Add(rhs, hb)
	rhs = curve.Add(rhs, curve.ScalarMul(proof.U, ab))
	// Compute inverse of left hand side
	// If both sides are equal then nP must be zero                               // (17)
	c := Pprime.Equal(rhs)

	return c, nil
}

/*
commitInnerProduct is responsible for calculating g^a.h^b.
*/
func commitInnerProduct(g, h []*Point, a, b []*big.Int) *Point {
	vga, _ := VectorExp(g, a)
	vhb, _ := VectorExp(h, b)
	result := curve.Add(vga, vhb)
	return result
}
