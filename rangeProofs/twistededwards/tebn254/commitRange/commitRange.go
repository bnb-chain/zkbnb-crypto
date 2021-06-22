package commitRange

import (
	"bytes"
	"math"
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

/*
	prove the value in the range
	@b: the secret value
	@r: the random value
	@g,h: two generators
*/
func Prove(b *big.Int, r *big.Int, g, h *Point, N uint) (proof *ComRangeProof, err error) {
	// check params
	if b == nil || r == nil || g == nil || h == nil || math.Pow(2, float64(N)) < float64(b.Int64()) {
		return nil, ErrInvalidRangeParams
	}
	// create a new proof
	proof = new(ComRangeProof)
	proof.G = g
	proof.H = h
	proof.As = make([]*Point, N)
	proof.Cas, proof.Cbs = make([]*Point, N), make([]*Point, N)
	proof.Fs, proof.Zas, proof.Zbs = make([]*big.Int, N), make([]*big.Int, N), make([]*big.Int, N)
	// buf to compute the challenge
	var buf bytes.Buffer
	buf.Write(g.Marshal())
	buf.Write(h.Marshal())
	// commitment to the value
	T, err := pedersen.Commit(b, r, g, h)
	if err != nil {
		return nil, err
	}
	// set proof
	proof.T = T
	buf.Write(T.Marshal())
	// convert the value into binary
	bsInt, _ := toBinary(b, int64(N))
	// get power of 2 vec
	powerof2Vec := PowerOfVec(big.NewInt(2), int64(N))
	// compute T' = \prod_{i=0}^{31}(A_i)^{2^i}
	Tprime := curve.ZeroPoint()
	// compute A_i = g^{b_i} h^{r_i}
	rs := make([]*big.Int, N)
	as := make([]*big.Int, N)
	ss := make([]*big.Int, N)
	ts := make([]*big.Int, N)
	// r' = \sum_{i=0}^{31} 2^i r_i
	rprime := big.NewInt(0)
	for i, bi := range bsInt {
		// r_i \gets_R \mathbb{Z}_p
		ri := curve.RandomValue()
		// compute A_i
		Ai := curve.Add(curve.ScalarMul(g, bi), curve.ScalarMul(h, ri))
		buf.Write(Ai.Marshal())
		// commitBinary to A_i
		Cai, Cbi, ai, si, ti, err := commitBinary(bi, g, h)
		if err != nil {
			return nil, err
		}
		buf.Write(Cai.Marshal())
		buf.Write(Cbi.Marshal())
		// update T'
		Tprime.Add(&Tprime, curve.ScalarMul(Ai, powerof2Vec[i]))
		// set proof
		proof.As[i] = Ai
		proof.Cas[i] = Cai
		proof.Cbs[i] = Cbi
		// set values
		rs[i] = ri
		as[i] = ai
		ss[i] = si
		ts[i] = ti

		rprime = ffmath.Add(rprime, ffmath.Multiply(ri, powerof2Vec[i]))
	}
	rprime = ffmath.Mod(rprime, Order)
	// prove T,T'
	A_T, A_Tprime, alpha_b, alpha_r, alpha_rprime, err := commitCommitmentSameValue(g, h)
	if err != nil {
		return nil, err
	}
	// write into buf
	buf.Write(A_T.Marshal())
	buf.Write(A_Tprime.Marshal())
	// compute the challenge
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return nil, err
	}
	// prove same value commitment
	zb, zr, zrprime, err := respondCommitmentSameValue(b, r, rprime, alpha_b, alpha_r, alpha_rprime, c)
	if err != nil {
		return nil, err
	}
	// set proof
	proof.Tprime = &Tprime
	proof.A_T = A_T
	proof.A_Tprime = A_Tprime
	proof.Zb = zb
	proof.Zr = zr
	proof.Zrprime = zrprime
	// prove binary
	for i, bi := range bsInt {
		fi, zai, zbi, err := respondBinary(bi, rs[i], as[i], ss[i], ts[i], c)
		if err != nil {
			return nil, err
		}
		proof.Fs[i] = fi
		proof.Zas[i] = zai
		proof.Zbs[i] = zbi
	}
	return proof, nil
}

/*
	Verify a CommitmentRangeProof
*/
func (proof *ComRangeProof) Verify() (bool, error) {
	if proof.As == nil || len(proof.As) != len(proof.Cas) || len(proof.As) != len(proof.Cbs) ||
		len(proof.As) != len(proof.Fs) || len(proof.As) != len(proof.Zas) || len(proof.As) != len(proof.Zbs) {
		return false, ErrInvalidRangeParams
	}
	// reconstruct buf
	var buf bytes.Buffer
	buf.Write(proof.G.Marshal())
	buf.Write(proof.H.Marshal())
	buf.Write(proof.T.Marshal())
	// set buf and
	// check if T' = (A_i)^{2^i}
	powerof2Vec := PowerOfVec(big.NewInt(2), int64(len(proof.As)))
	Tprime_check := curve.ZeroPoint()
	for i, Ai := range proof.As {
		buf.Write(Ai.Marshal())
		buf.Write(proof.Cas[i].Marshal())
		buf.Write(proof.Cbs[i].Marshal())
		Tprime_check.Add(&Tprime_check, curve.ScalarMul(Ai, powerof2Vec[i]))
	}
	// check sum
	if !Tprime_check.Equal(proof.Tprime) {
		return false, ErrInvalidRangeParams
	}
	buf.Write(proof.A_T.Marshal())
	buf.Write(proof.A_Tprime.Marshal())
	// compute the challenge
	c, err := util.HashToInt(buf, zmimc.Hmimc)
	if err != nil {
		return false, err
	}
	for i, Ai := range proof.As {
		binaryRes, err := verifyBinary(Ai, proof.Cas[i], proof.Cbs[i], proof.G, proof.H, proof.Fs[i], proof.Zas[i], proof.Zbs[i], c)
		if err != nil || !binaryRes {
			return false, err
		}
	}
	sameComRes, err := verifyCommitmentSameValue(proof.A_T, proof.A_Tprime, proof.T, proof.Tprime, proof.G, proof.H, proof.Zb, proof.Zr, proof.Zrprime, c)
	if err != nil || !sameComRes {
		return false, err
	}
	return true, nil
}

/*
	commitBinary makes a random commitment to binary proof
	@b: binary value
	@g,h: generators
*/
func commitBinary(b *big.Int, g, h *Point) (Ca, Cb *Point, a, s, t *big.Int, err error) {
	if b == nil {
		return nil, nil, nil, nil, nil, errInvalidBinaryParams
	}
	// a,s,t \gets_r \mathbb{Z}_p
	a, s, t = curve.RandomValue(), curve.RandomValue(), curve.RandomValue()
	Ca, err = pedersen.Commit(a, s, g, h)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	Cb, err = pedersen.Commit(ffmath.Multiply(a, b), t, g, h)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return Ca, Cb, a, s, t, nil
}

/*
	respondBinary makes a response to binary proof
	@b: binary value
	@r: random value
	@a,s,t: random values for random commitments
	@c: the challenge
*/
func respondBinary(b, r, a, s, t *big.Int, c *big.Int) (f, za, zb *big.Int, err error) {
	if b == nil || r == nil || a == nil || s == nil || t == nil || c == nil {
		return nil, nil, nil, errInvalidBinaryParams
	}
	// f = bc + a
	f = ffmath.AddMod(ffmath.Multiply(c, b), a, Order)
	// za = rc + s
	za = ffmath.AddMod(ffmath.Multiply(r, c), s, Order)
	// zb = r(c - f) + t
	zb = ffmath.Sub(c, f)
	zb = ffmath.Multiply(r, zb)
	zb = ffmath.AddMod(zb, t, Order)
	return f, za, zb, nil
}

/*
	verifyBinary verify a binary proof
	@A: pedersen commitment for the binary value
	@Ca,Cb: binary proof commitment
	@g,h: generators
	@f,za,zb: binary proof response
	@c: the challenge
*/
func verifyBinary(A, Ca, Cb, g, h *Point, f, za, zb *big.Int, c *big.Int) (bool, error) {
	if A == nil || Ca == nil || Cb == nil || f == nil || za == nil || zb == nil || c == nil {
		return false, errInvalidBinaryParams
	}
	// A^c Ca == Com(f,za)
	r1, err := pedersen.Commit(f, za, g, h)
	if err != nil {
		return false, err
	}
	l1 := curve.Add(curve.ScalarMul(A, c), Ca)
	l1r1 := l1.Equal(r1)
	if !l1r1 {
		return false, nil
	}
	// A^{c-f} Cb == Com(0,zb)
	r2 := curve.ScalarMul(h, zb)
	l2 := curve.Add(curve.ScalarMul(A, ffmath.Sub(c, f)), Cb)
	l2r2 := l2.Equal(r2)
	return l2r2, nil
}

/*
	commitCommitmentSameValue makes a random commitment to the same value pedersen commitment proof
	@g,h: generators
*/
func commitCommitmentSameValue(g, h *Point) (A_T, A_Tprime *Point, alpha_b, alpha_r, alpha_rprime *big.Int, err error) {
	// a,s,t \gets_R \mathbb{Z}_p
	alpha_b = curve.RandomValue()
	alpha_r = curve.RandomValue()
	alpha_rprime = curve.RandomValue()
	g_alphab := curve.ScalarMul(g, alpha_b)
	A_T = curve.Add(g_alphab, curve.ScalarMul(h, alpha_r))
	A_Tprime = curve.Add(g_alphab, curve.ScalarMul(h, alpha_rprime))
	return A_T, A_Tprime, alpha_b, alpha_r, alpha_rprime, nil
}

/*
	respondCommitmentSameValue makes a response to the same value pedersen commitment proof
	@b: the value
	@r: the random value for b
	@rprime: another random value for b
	@alpha_b,alpha_r,alpha_rprime: random values generated in commit phase
	@c: the challenge
*/
func respondCommitmentSameValue(b, r, rprime, alpha_b, alpha_r, alpha_rprime *big.Int, c *big.Int) (zb, zr, zrprime *big.Int, err error) {
	if b == nil || r == nil || rprime == nil || alpha_b == nil || alpha_r == nil || alpha_rprime == nil || c == nil {
		return nil, nil, nil, errInvalidCommitmentParams
	}
	// zb = alpha_b + cb
	zb = ffmath.AddMod(alpha_b, ffmath.Multiply(c, b), Order)
	// zr = alpha_r + cr
	zr = ffmath.AddMod(alpha_r, ffmath.Multiply(c, r), Order)
	// zrprime = alpha_rprime + c rprime
	zrprime = ffmath.AddMod(alpha_rprime, ffmath.Multiply(c, rprime), Order)
	return zb, zr, zrprime, nil
}

/*
	verifyCommitmentSameValue verify the same value pedersen commitment proof
	@A_T,A_Tprime: commitment values generated in commit phase
	@T,Tprime: two pedersen commitments for the same b
	@g,h: generators
	@zb,zr,zrprime: commitmentSameValue response
	@c: the challenge
*/
func verifyCommitmentSameValue(A_T, A_Tprime, T, Tprime, g, h *Point, zb, zr, zrprime *big.Int, c *big.Int) (bool, error) {
	if zb == nil || zr == nil || zrprime == nil || A_T == nil || A_Tprime == nil || T == nil || Tprime == nil || g == nil || h == nil || c == nil {
		return false, errInvalidCommitmentParams
	}
	// g^{zb} h^{zr} == A_T T^c
	gzb := curve.ScalarMul(g, zb)
	l1 := curve.Add(gzb, curve.ScalarMul(h, zr))
	r1 := curve.Add(A_T, curve.ScalarMul(T, c))
	if !l1.Equal(r1) {
		return false, nil
	}
	// g^{zb} h^{zrprime} == A_T' T'^c
	hzrprime := curve.ScalarMul(h, zrprime)
	l2 := curve.Add(gzb, hzrprime)
	r2 := curve.Add(A_Tprime, curve.ScalarMul(Tprime, c))
	return l2.Equal(r2), nil
}
