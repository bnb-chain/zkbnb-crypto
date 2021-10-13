package zecrey

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
)

type TransferProof struct {
	// sub proofs
	SubProofs [TransferSubProofCount]*TransferSubProof
	// commitment for \sum_{i=1}^n b_i^{\Delta}
	A_sum *Point
	Z_sum *big.Int
	// challenges
	C1, C2 *big.Int
	G, H   *Point
	Fee    uint64
}

func (proof *TransferProof) Bytes() []byte {
	proofBytes := make([]byte, TransferProofSize)
	for i := 0; i < TransferSubProofCount; i++ {
		copy(proofBytes[i*TransferSubProofSize:(i+1)*TransferSubProofSize], proof.SubProofs[i].Bytes())
	}
	copy(proofBytes[TransferSubProofCount*TransferSubProofSize:TransferSubProofCount*TransferSubProofSize+PointSize], proof.A_sum.Marshal())
	copy(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize:TransferSubProofCount*TransferSubProofSize+PointSize*2], proof.Z_sum.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*2:TransferSubProofCount*TransferSubProofSize+PointSize*3], proof.C1.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*3:TransferSubProofCount*TransferSubProofSize+PointSize*4], proof.C2.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*4:TransferSubProofCount*TransferSubProofSize+PointSize*5], proof.G.Marshal())
	copy(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*5:TransferSubProofCount*TransferSubProofSize+PointSize*6], proof.H.Marshal())
	FeeBytes := make([]byte, EightBytes)
	binary.BigEndian.PutUint64(FeeBytes, proof.Fee)
	copy(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*6:TransferSubProofCount*TransferSubProofSize+PointSize*6+EightBytes], FeeBytes)
	return proofBytes
}

func (proof *TransferProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseTransferProofBytes(proofBytes []byte) (proof *TransferProof, err error) {
	if len(proofBytes) != TransferProofSize {
		return nil, ErrInvalidTransferProofSize
	}
	proof = new(TransferProof)
	for i := 0; i < TransferSubProofCount; i++ {
		proof.SubProofs[i], err = ParseTransferSubProofBytes(proofBytes[i*TransferSubProofSize : (i+1)*TransferSubProofSize])
		if err != nil {
			return nil, err
		}
	}
	proof.A_sum, err = curve.FromBytes(proofBytes[TransferSubProofCount*TransferSubProofSize : TransferSubProofCount*TransferSubProofSize+PointSize])
	if err != nil {
		return nil, err
	}
	proof.Z_sum = new(big.Int).SetBytes(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize : TransferSubProofCount*TransferSubProofSize+PointSize*2])
	proof.C1 = new(big.Int).SetBytes(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*2 : TransferSubProofCount*TransferSubProofSize+PointSize*3])
	proof.C2 = new(big.Int).SetBytes(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*3 : TransferSubProofCount*TransferSubProofSize+PointSize*4])
	proof.G, err = curve.FromBytes(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*4 : TransferSubProofCount*TransferSubProofSize+PointSize*5])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*5 : TransferSubProofCount*TransferSubProofSize+PointSize*6])
	if err != nil {
		return nil, err
	}
	proof.Fee = binary.BigEndian.Uint64(proofBytes[TransferSubProofCount*TransferSubProofSize+PointSize*6 : TransferSubProofCount*TransferSubProofSize+PointSize*6+EightBytes])
	return proof, nil
}

func ParseTransferProofStr(proofStr string) (*TransferProof, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseTransferProofBytes(proofBytes)
}

type TransferSubProof struct {
	// sigma protocol commitment values
	A_CLDelta, A_CRDelta, A_Y1, A_Y2, A_T, A_pk, A_TDivCPrime *Point
	// respond values
	Z_r, Z_bDelta, Z_rstar1, Z_rstar2, Z_bstar1, Z_bstar2, Z_rbar, Z_bprime, Z_sk, Z_skInv *big.Int
	// range proof
	BStarRangeProof *RangeProof
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
}

func (proof *TransferSubProof) Bytes() []byte {
	proofBytes := make([]byte, TransferSubProofSize)
	// A_CLDelta, A_CRDelta, A_Y1, , A_T, A_pk, A_TDivCPrime
	copy(proofBytes[:PointSize], proof.A_CLDelta.Marshal())
	copy(proofBytes[PointSize:PointSize*2], proof.A_CRDelta.Marshal())
	copy(proofBytes[PointSize*2:PointSize*3], proof.A_Y1.Marshal())
	copy(proofBytes[PointSize*3:PointSize*4], proof.A_Y2.Marshal())
	copy(proofBytes[PointSize*4:PointSize*5], proof.A_T.Marshal())
	copy(proofBytes[PointSize*5:PointSize*6], proof.A_pk.Marshal())
	copy(proofBytes[PointSize*6:PointSize*7], proof.A_TDivCPrime.Marshal())
	// Z_r, Z_bDelta, Z_rstar1, Z_rstarSubrbar, Z_rbar, Z_bprime, Z_sk, Z_skInv
	copy(proofBytes[PointSize*7:PointSize*8], proof.Z_r.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*8:PointSize*9], proof.Z_bDelta.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*9:PointSize*10], proof.Z_rstar1.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*10:PointSize*11], proof.Z_rstar2.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*11:PointSize*12], proof.Z_bstar1.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*12:PointSize*13], proof.Z_bstar2.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*13:PointSize*14], proof.Z_rbar.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*14:PointSize*15], proof.Z_bprime.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*15:PointSize*16], proof.Z_sk.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*16:PointSize*17], proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	// C
	C := proof.C.Bytes()
	copy(proofBytes[PointSize*17:PointSize*19], C[:])
	CDelta := proof.CDelta.Bytes()
	copy(proofBytes[PointSize*19:PointSize*21], CDelta[:])
	copy(proofBytes[PointSize*21:PointSize*22], proof.T.Marshal())
	copy(proofBytes[PointSize*22:PointSize*23], proof.Y.Marshal())
	copy(proofBytes[PointSize*23:PointSize*24], proof.Pk.Marshal())
	copy(proofBytes[PointSize*24:PointSize*24+RangeProofSize], proof.BStarRangeProof.Bytes())
	return proofBytes
}

func ParseTransferSubProofBytes(proofBytes []byte) (proof *TransferSubProof, err error) {
	if len(proofBytes) != TransferSubProofSize {
		return nil, ErrInvalidTransferSubProofSize
	}
	proof = new(TransferSubProof)
	proof.A_CLDelta, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.A_CRDelta, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.A_Y1, err = curve.FromBytes(proofBytes[PointSize*2 : PointSize*3])
	if err != nil {
		return nil, err
	}
	proof.A_Y2, err = curve.FromBytes(proofBytes[PointSize*3 : PointSize*4])
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
	proof.Z_rstar1 = new(big.Int).SetBytes(proofBytes[PointSize*9 : PointSize*10])
	proof.Z_rstar2 = new(big.Int).SetBytes(proofBytes[PointSize*10 : PointSize*11])
	proof.Z_bstar1 = new(big.Int).SetBytes(proofBytes[PointSize*11 : PointSize*12])
	proof.Z_bstar2 = new(big.Int).SetBytes(proofBytes[PointSize*12 : PointSize*13])
	proof.Z_rbar = new(big.Int).SetBytes(proofBytes[PointSize*13 : PointSize*14])
	proof.Z_bprime = new(big.Int).SetBytes(proofBytes[PointSize*14 : PointSize*15])
	proof.Z_sk = new(big.Int).SetBytes(proofBytes[PointSize*15 : PointSize*16])
	proof.Z_skInv = new(big.Int).SetBytes(proofBytes[PointSize*16 : PointSize*17])
	proof.C, err = twistedElgamal.FromBytes(proofBytes[PointSize*17 : PointSize*19])
	if err != nil {
		return nil, err
	}
	proof.CDelta, err = twistedElgamal.FromBytes(proofBytes[PointSize*19 : PointSize*21])
	if err != nil {
		return nil, err
	}
	proof.T, err = curve.FromBytes(proofBytes[PointSize*21 : PointSize*22])
	if err != nil {
		return nil, err
	}
	proof.Y, err = curve.FromBytes(proofBytes[PointSize*22 : PointSize*23])
	if err != nil {
		return nil, err
	}
	proof.Pk, err = curve.FromBytes(proofBytes[PointSize*23 : PointSize*24])
	if err != nil {
		return nil, err
	}
	proof.BStarRangeProof, err = ctrange.FromBytes(proofBytes[PointSize*24 : PointSize*24+RangeProofSize])
	if err != nil {
		return nil, err
	}
	return proof, nil
}

type TransferProofRelation struct {
	Statements []*TransferProofStatement
	R_sum      *big.Int
	Fee        uint64
	G          *Point
	H          *Point
	AssetId    uint32
}

func NewTransferProofRelation(assetId uint32, fee uint64) (*TransferProofRelation, error) {
	if !validUint64(fee) {
		log.Println("[NewTransferProofRelation] err: invalid fee")
		return nil, errors.New("[NewTransferProofRelation] err: invalid fee")
	}
	return &TransferProofRelation{G: G, H: H, AssetId: assetId, Fee: fee, R_sum: big.NewInt(0)}, nil
}

func (relation *TransferProofRelation) AddStatement(C *ElGamalEnc, pk *Point, b uint64, bDelta int64, sk *big.Int) (err error) {
	// check params
	if !validUint64(b) || !validInt64(bDelta) ||
		!notNullElGamal(C) || !curve.IsInSubGroup(pk) {
		log.Println("[AddStatement] invalid params")
		return ErrInvalidParams
	}
	// if the user owns the account, should do more verifications
	if sk != nil {
		oriPk := curve.ScalarBaseMul(sk)
		// 1. should be the same public key
		// 2. b should not be null and larger than zero
		// 3. bDelta should smaller than zero
		if !oriPk.Equal(pk) {
			log.Println("[TransferProofRelation AddStatement] err: inconsistent public key")
			return ErrInconsistentPublicKey
		}
		// check if the b is correct
		hb := curve.Add(C.CR, curve.Neg(curve.ScalarMul(C.CL, ffmath.ModInverse(sk, Order))))
		hbCheck := curve.ScalarMul(H, big.NewInt(int64(b)))
		if !hb.Equal(hbCheck) {
			log.Println("[TransferProofRelation AddStatement] err: incorrect balance")
			return ErrIncorrectBalance
		}
		if b == 0 && relation.Fee > 0 {
			log.Println("[TransferProofRelation AddStatement] err: insufficient balance")
			return ErrInsufficientBalance
		}
		if bDelta > 0 {
			log.Println("[TransferProofRelation AddStatement] err: invalid delta")
			return ErrInvalidDelta
		}
	}
	// now b != nil
	var (
		CDelta *ElGamalEnc
		T      *Point
		bPrime uint64
		bStar  uint64
		r      *big.Int
		rBar   *big.Int
	)
	// if user knows b which means that he owns the account
	if sk != nil {
		// b' = b + b^{\Delta}
		if int64(b)+bDelta < 0 {
			log.Println("[TransferProofRelation AddStatement] err: insufficient balance")
			return ErrInsufficientBalance
		}
		bPrime = uint64(int64(b) + bDelta)
		bStar = bPrime
	} else {
		bStar = uint64(bDelta)
		bPrime = 0
	}
	// r \gets_R \mathbb{Z}_p
	r = curve.RandomValue()
	// add into r_sum
	relation.R_sum = ffmath.Add(relation.R_sum, r)
	// C^{\Delta} = (pk^r, g^r h^{b^{\Delta}})
	CDelta, err = twistedElgamal.Enc(big.NewInt(bDelta), r, pk)
	if err != nil {
		log.Println("[TransferProofRelation AddStatement] err info:", err)
		return err
	}
	// \bar{r} \gets_R \mathbb{Z}_p
	rBar = curve.RandomValue()
	// T = g^{\bar{r}} h^{b'}
	T, err = pedersen.Commit(rBar, big.NewInt(int64(bPrime)), G, H)
	if err != nil {
		log.Println("[TransferProofRelation AddStatement] err info:", err)
		return err
	}
	// create statement
	statement := &TransferProofStatement{
		// ------------- public ---------------------
		C:      C,
		CDelta: CDelta,
		T:      T,
		Pk:     pk,
		// ----------- private ---------------------
		BDelta: bDelta,
		BStar:  bStar,
		BPrime: bPrime,
		Sk:     sk,
		R:      r,
		RBar:   rBar,
	}
	relation.Statements = append(relation.Statements, statement)
	return nil
}

type TransferProofStatement struct {
	// ------------- public ---------------------
	// original balance enc
	C *ElGamalEnc
	// delta balance enc
	CDelta *ElGamalEnc
	// new pedersen commitment for new balance
	T *Point
	// public key
	Pk *Point
	// ----------- private ---------------------
	// delta balance
	BDelta int64
	// copy for delta balance or new balance
	BStar uint64
	// new balance
	BPrime uint64
	// private key
	Sk *big.Int
	// random value for CDelta
	R *big.Int
	// random value for T
	RBar *big.Int
}

type transferCommitValues struct {
	// random values
	alpha_r, alpha_bDelta,
	alpha_rstar, alpha_rbar, alpha_bprime,
	alpha_sk, alpha_skInv *big.Int
	// commit
	A_CLDelta, A_CRDelta, A_Y1, A_Y2,
	A_T, A_pk, A_TDivCPrime *Point
}

func FakeTransferProof() *TransferProof {
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := uint64(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := uint64(3)
	r3 := curve.RandomValue()
	b1Enc, _ := twistedElgamal.Enc(big.NewInt(int64(b1)), r1, pk1)
	b2Enc, _ := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, _ := twistedElgamal.Enc(big.NewInt(int64(b3)), r3, pk3)
	relation, _ := NewTransferProofRelation(1, 0)
	relation.AddStatement(b2Enc, pk2, 0, 2, nil)
	relation.AddStatement(b1Enc, pk1, b1, -4, sk1)
	relation.AddStatement(b3Enc, pk3, b3, 2, nil)
	transferProof, _ := ProveTransfer(relation)
	return transferProof
}
