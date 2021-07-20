package zecrey

import (
	"encoding/base64"
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

type PTransferProof struct {
	// sub proofs
	SubProofs [TransferSubProofCount]*PTransferSubProof
	// commitment for \sum_{i=1}^n b_i^{\Delta}
	A_sum *Point
	// A_Pt
	A_Pt *Point
	// z_tsk
	Z_tsk *big.Int
	// Pt = (Ht)^{sk_i}
	Pt *Point
	// challenges
	C1, C2   *big.Int
	G, H, Ht *Point
	Fee      *big.Int
}

func (proof *PTransferProof) Bytes() []byte {
	proofBytes := make([]byte, TransferProofSize)
	for i := 0; i < TransferSubProofCount; i++ {
		copy(proofBytes[i*TransferSubProofSize:(i+1)*TransferSubProofSize], proof.SubProofs[i].Bytes())
	}
	copy(proofBytes[3*TransferSubProofSize:3*TransferSubProofSize+PointSize], proof.A_sum.Marshal())
	copy(proofBytes[3*TransferSubProofSize+PointSize:3*TransferSubProofSize+PointSize*2], proof.A_Pt.Marshal())
	copy(proofBytes[3*TransferSubProofSize+PointSize*2:3*TransferSubProofSize+PointSize*3], proof.Z_tsk.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[3*TransferSubProofSize+PointSize*3:3*TransferSubProofSize+PointSize*4], proof.Pt.Marshal())
	copy(proofBytes[3*TransferSubProofSize+PointSize*4:3*TransferSubProofSize+PointSize*5], proof.C1.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[3*TransferSubProofSize+PointSize*5:3*TransferSubProofSize+PointSize*6], proof.C2.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[3*TransferSubProofSize+PointSize*6:3*TransferSubProofSize+PointSize*7], proof.G.Marshal())
	copy(proofBytes[3*TransferSubProofSize+PointSize*7:3*TransferSubProofSize+PointSize*8], proof.H.Marshal())
	copy(proofBytes[3*TransferSubProofSize+PointSize*8:3*TransferSubProofSize+PointSize*9], proof.Ht.Marshal())
	copy(proofBytes[3*TransferSubProofSize+PointSize*9:3*TransferSubProofSize+PointSize*9+8], proof.Fee.FillBytes(make([]byte, 8)))
	return proofBytes
}

func (proof *PTransferProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseTransferProofBytes(proofBytes []byte) (proof *PTransferProof, err error) {
	if len(proofBytes) != TransferProofSize {
		return nil, ErrInvalidTransferProofSize
	}
	proof = new(PTransferProof)
	for i := 0; i < TransferSubProofCount; i++ {
		proof.SubProofs[i], err = ParseTransferSubProofBytes(proofBytes[i*TransferSubProofSize : (i+1)*TransferSubProofSize])
		if err != nil {
			return nil, err
		}
	}
	proof.A_sum, err = curve.FromBytes(proofBytes[3*TransferSubProofSize : 3*TransferSubProofSize+PointSize])
	if err != nil {
		return nil, err
	}
	proof.A_Pt, err = curve.FromBytes(proofBytes[3*TransferSubProofSize+PointSize : 3*TransferSubProofSize+PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.Z_tsk = new(big.Int).SetBytes(proofBytes[3*TransferSubProofSize+PointSize*2 : 3*TransferSubProofSize+PointSize*3])
	proof.Pt, err = curve.FromBytes(proofBytes[3*TransferSubProofSize+PointSize*3 : 3*TransferSubProofSize+PointSize*4])
	if err != nil {
		return nil, err
	}
	proof.C1 = new(big.Int).SetBytes(proofBytes[3*TransferSubProofSize+PointSize*4 : 3*TransferSubProofSize+PointSize*5])
	proof.C2 = new(big.Int).SetBytes(proofBytes[3*TransferSubProofSize+PointSize*5 : 3*TransferSubProofSize+PointSize*6])
	proof.G, err = curve.FromBytes(proofBytes[3*TransferSubProofSize+PointSize*6 : 3*TransferSubProofSize+PointSize*7])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[3*TransferSubProofSize+PointSize*7 : 3*TransferSubProofSize+PointSize*8])
	if err != nil {
		return nil, err
	}
	proof.Ht, err = curve.FromBytes(proofBytes[3*TransferSubProofSize+PointSize*8 : 3*TransferSubProofSize+PointSize*9])
	if err != nil {
		return nil, err
	}
	proof.Fee = new(big.Int).SetBytes(proofBytes[3*TransferSubProofSize+PointSize*9 : 3*TransferSubProofSize+PointSize*9+8])
	return proof, nil
}

func ParseTransferProofStr(proofStr string) (*PTransferProof, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseTransferProofBytes(proofBytes)
}

type PTransferSubProof struct {
	// sigma protocol commitment values
	A_CLDelta, A_CRDelta, A_YDivCRDelta, A_YDivT, A_T, A_pk, A_TDivCPrime *Point
	// respond values
	Z_r, Z_bDelta, Z_rstarSubr, Z_rstarSubrbar, Z_rbar, Z_bprime, Z_sk, Z_skInv *big.Int
	// range proof
	CRangeProof *commitRange.ComRangeProof
	// common inputs
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CDelta *ElGamalEnc
	// new pedersen commitment for new balance
	T *Point
	// new pedersen commitment for deleta balance or new balance
	Y *Point
	// public key
	Pk *Point
	// T (C_R + C_R^{\Delta})^{-1}
	TCRprimeInv *Point
	// (C_L + C_L^{\Delta})^{-1}
	CLprimeInv *Point
}

func (proof *PTransferSubProof) Bytes() []byte {
	proofBytes := make([]byte, TransferSubProofSize)
	// A_CLDelta, A_CRDelta, A_YDivCRDelta, A_YDivT, A_T, A_pk, A_TDivCPrime
	copy(proofBytes[:PointSize], proof.A_CLDelta.Marshal())
	copy(proofBytes[PointSize:PointSize*2], proof.A_CRDelta.Marshal())
	copy(proofBytes[PointSize*2:PointSize*3], proof.A_YDivCRDelta.Marshal())
	copy(proofBytes[PointSize*3:PointSize*4], proof.A_YDivT.Marshal())
	copy(proofBytes[PointSize*4:PointSize*5], proof.A_T.Marshal())
	copy(proofBytes[PointSize*5:PointSize*6], proof.A_pk.Marshal())
	copy(proofBytes[PointSize*6:PointSize*7], proof.A_TDivCPrime.Marshal())
	// Z_r, Z_bDelta, Z_rstarSubr, Z_rstarSubrbar, Z_rbar, Z_bprime, Z_sk, Z_skInv
	copy(proofBytes[PointSize*7:PointSize*8], proof.Z_r.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*8:PointSize*9], proof.Z_bDelta.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*9:PointSize*10], proof.Z_rstarSubr.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*10:PointSize*11], proof.Z_rstarSubrbar.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*11:PointSize*12], proof.Z_rbar.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*12:PointSize*13], proof.Z_bprime.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*13:PointSize*14], proof.Z_sk.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*14:PointSize*15], proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	// C
	C := proof.C.Bytes()
	copy(proofBytes[PointSize*15:PointSize*17], C[:])
	CDelta := proof.CDelta.Bytes()
	copy(proofBytes[PointSize*17:PointSize*19], CDelta[:])
	copy(proofBytes[PointSize*19:PointSize*20], proof.T.Marshal())
	copy(proofBytes[PointSize*20:PointSize*21], proof.Y.Marshal())
	copy(proofBytes[PointSize*21:PointSize*22], proof.Pk.Marshal())
	copy(proofBytes[PointSize*22:PointSize*23], proof.TCRprimeInv.Marshal())
	copy(proofBytes[PointSize*23:PointSize*24], proof.CLprimeInv.Marshal())
	copy(proofBytes[PointSize*24:], proof.CRangeProof.Bytes())
	return proofBytes
}

func ParseTransferSubProofBytes(proofBytes []byte) (proof *PTransferSubProof, err error) {
	if len(proofBytes) != TransferSubProofSize {
		return nil, ErrInvalidTransferSubProofSize
	}
	proof = new(PTransferSubProof)
	proof.A_CLDelta, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.A_CRDelta, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.A_YDivCRDelta, err = curve.FromBytes(proofBytes[PointSize*2 : PointSize*3])
	if err != nil {
		return nil, err
	}
	proof.A_YDivT, err = curve.FromBytes(proofBytes[PointSize*3 : PointSize*4])
	if err != nil {
		return nil, err
	}
	proof.A_T, err = curve.FromBytes(proofBytes[PointSize*4 : PointSize*5])
	if err != nil {
		return nil, err
	}
	proof.A_pk, err = curve.FromBytes(proofBytes[PointSize*5 : PointSize*6])
	if err != nil {
		return nil, err
	}
	proof.A_TDivCPrime, err = curve.FromBytes(proofBytes[PointSize*6 : PointSize*7])
	if err != nil {
		return nil, err
	}
	proof.Z_r = new(big.Int).SetBytes(proofBytes[PointSize*7 : PointSize*8])
	proof.Z_bDelta = new(big.Int).SetBytes(proofBytes[PointSize*8 : PointSize*9])
	proof.Z_rstarSubr = new(big.Int).SetBytes(proofBytes[PointSize*9 : PointSize*10])
	proof.Z_rstarSubrbar = new(big.Int).SetBytes(proofBytes[PointSize*10 : PointSize*11])
	proof.Z_rbar = new(big.Int).SetBytes(proofBytes[PointSize*11 : PointSize*12])
	proof.Z_bprime = new(big.Int).SetBytes(proofBytes[PointSize*12 : PointSize*13])
	proof.Z_sk = new(big.Int).SetBytes(proofBytes[PointSize*13 : PointSize*14])
	proof.Z_skInv = new(big.Int).SetBytes(proofBytes[PointSize*14 : PointSize*15])
	proof.C, err = twistedElgamal.FromBytes(proofBytes[PointSize*15 : PointSize*17])
	if err != nil {
		return nil, err
	}
	proof.CDelta, err = twistedElgamal.FromBytes(proofBytes[PointSize*17 : PointSize*19])
	if err != nil {
		return nil, err
	}
	proof.T, err = curve.FromBytes(proofBytes[PointSize*19 : PointSize*20])
	if err != nil {
		return nil, err
	}
	proof.Y, err = curve.FromBytes(proofBytes[PointSize*20 : PointSize*21])
	if err != nil {
		return nil, err
	}
	proof.Pk, err = curve.FromBytes(proofBytes[PointSize*21 : PointSize*22])
	if err != nil {
		return nil, err
	}
	proof.TCRprimeInv, err = curve.FromBytes(proofBytes[PointSize*22 : PointSize*23])
	if err != nil {
		return nil, err
	}
	proof.CLprimeInv, err = curve.FromBytes(proofBytes[PointSize*23 : PointSize*24])
	if err != nil {
		return nil, err
	}
	proof.CRangeProof, err = commitRange.FromBytes(proofBytes[PointSize*24:])
	if err != nil {
		return nil, err
	}
	return proof, nil
}

type PTransferProofRelation struct {
	Statements []*PTransferProofStatement
	Fee        *big.Int
	G          *Point
	H          *Point
	Ht         *Point
	Pt         *Point
	TokenId    uint32
}

func NewPTransferProofRelation(tokenId uint32, fee *big.Int) (*PTransferProofRelation, error) {
	if fee.Cmp(Zero) < 0 {
		return nil, ErrInvalidParams
	}
	Ht := curve.ScalarMul(H, big.NewInt(int64(tokenId)))
	return &PTransferProofRelation{G: G, H: H, Ht: Ht, TokenId: tokenId, Fee: fee}, nil
}

func (relation *PTransferProofRelation) AddStatement(C *ElGamalEnc, pk *Point, b *big.Int, bDelta *big.Int, sk *big.Int) (err error) {
	// check params
	if C == nil || pk == nil {
		return ErrInvalidParams
	}
	// if the user owns the account, should do more verifications
	if sk != nil {
		oriPk := curve.ScalarBaseMul(sk)
		// 1. should be the same public key
		// 2. b should not be null and larger than zero
		// 3. bDelta should smaller than zero
		if !oriPk.Equal(pk) {
			return ErrInconsistentPublicKey
		}
		// check if the b is correct
		hb := curve.Add(C.CR, curve.Neg(curve.ScalarMul(C.CL, ffmath.ModInverse(sk, Order))))
		hbCheck := curve.ScalarMul(H, b)
		if !hb.Equal(hbCheck) {
			return ErrIncorrectBalance
		}
		if b == nil || b.Cmp(Zero) < 0 {
			return ErrInsufficientBalance
		}
		if bDelta.Cmp(Zero) > 0 {
			return ErrInvalidDelta
		}
		// add Pt
		Pt := curve.ScalarMul(relation.Ht, sk)
		relation.Pt = Pt
	}
	// now b != nil
	var (
		CDelta *ElGamalEnc
		T      *Point
		Y      *Point
		bPrime *big.Int
		bStar  *big.Int
		r      *big.Int
		rBar   *big.Int
		rStar  *big.Int
		rs     [RangeMaxBits]*big.Int
	)
	// if user knows b which means that he owns the account
	if b != nil && sk != nil {
		// b' = b + b^{\Delta}
		bPrime = ffmath.Add(b, bDelta)
		// bPrime should bigger than zero
		if bPrime.Cmp(Zero) < 0 {
			return ErrInsufficientBalance
		}
		bStar = bPrime
	} else {
		bStar = bDelta
		bPrime = PadSecret
	}
	// r \gets_R \mathbb{Z}_p
	r = curve.RandomValue()
	// C^{\Delta} = (pk^r, g^r h^{b^{\Delta}})
	CDelta, err = twistedElgamal.Enc(bDelta, r, pk)
	if err != nil {
		return err
	}
	// r^{\star} \gets_R \mathbb{Z}_p
	rStar = big.NewInt(0)
	for i := 0; i < RangeMaxBits; i++ {
		rs[i] = curve.RandomValue()
		rStar.Add(rStar, rs[i])
	}
	rStar.Mod(rStar, Order)
	// \bar{r} \gets_R \mathbb{Z}_p
	rBar = curve.RandomValue()
	// T = g^{\bar{r}} h^{b'}
	T, err = pedersen.Commit(rBar, bPrime, G, H)
	if err != nil {
		return err
	}
	Y, err = pedersen.Commit(rStar, bStar, G, H)
	if err != nil {
		return err
	}
	// create statement
	statement := &PTransferProofStatement{
		// ------------- public ---------------------
		C:           C,
		CDelta:      CDelta,
		T:           T,
		Y:           Y,
		Pk:          pk,
		TCRprimeInv: curve.Add(T, curve.Neg(curve.Add(C.CR, CDelta.CR))),
		CLprimeInv:  curve.Neg(curve.Add(C.CL, CDelta.CL)),
		// ----------- private ---------------------
		BDelta: bDelta,
		BStar:  bStar,
		BPrime: bPrime,
		Sk:     sk,
		R:      r,
		RBar:   rBar,
		RStar:  rStar,
		Rs:     rs,
	}
	relation.Statements = append(relation.Statements, statement)
	return nil
}

type PTransferProofStatement struct {
	// ------------- public ---------------------
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CDelta *ElGamalEnc
	// new pedersen commitment for new balance
	T *Point
	// new pedersen commitment for deleta balance or new balance
	Y *Point
	// public key
	Pk *Point
	// T (C_R + C_R^{\Delta})^{-1}
	TCRprimeInv *Point
	// (C_L + C_L^{\Delta})^{-1}
	CLprimeInv *Point
	// ----------- private ---------------------
	// delta balance
	BDelta *big.Int
	// copy for delta balance or new balance
	BStar *big.Int
	// new balance
	BPrime *big.Int
	// private key
	Sk *big.Int
	// random value for CDelta
	R *big.Int
	// random value for T
	RBar *big.Int
	// random value for Y
	RStar *big.Int
	// rs
	Rs [RangeMaxBits]*big.Int
	// token id
	TokenId uint32
}

type transferCommitValues struct {
	// random values
	alpha_r, alpha_bDelta, alpha_rstarSubr,
	alpha_rstarSubrbar, alpha_rbar, alpha_bprime,
	alpha_sk, alpha_skInv *big.Int
	// commit
	A_CLDelta, A_CRDelta, A_YDivCRDelta, A_YDivT,
	A_T, A_pk, A_TDivCPrime *Point
}

func FakeTransferProof() *PTransferProof {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	b1Enc, _ := twistedElgamal.Enc(b1, r1, pk1)
	b2Enc, _ := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, _ := twistedElgamal.Enc(b3, r3, pk3)
	relation, _ := NewPTransferProofRelation(1, big.NewInt(0))
	relation.AddStatement(b2Enc, pk2, nil, big.NewInt(2), nil)
	relation.AddStatement(b1Enc, pk1, b1, big.NewInt(-4), sk1)
	relation.AddStatement(b3Enc, pk3, b3, big.NewInt(2), nil)
	transferProof, _ := ProvePTransfer(relation)
	return transferProof
}
