package zecrey

import (
	"encoding/base64"
	"errors"
	"log"
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
)

type TransferProof struct {
	// sub proofs
	SubProofs [TransferSubProofCount]*TransferSubProof
	// commitment for \sum_{i=1}^n b_i^{\Delta}
	A_sum *Point
	Z_sum *big.Int
	// challenges
	C1, C2  *big.Int
	GasFee  uint64
	AssetId uint32
}

func (proof *TransferProof) Bytes() []byte {
	proofBytes := make([]byte, TransferProofSize)
	offset := 0
	for i := 0; i < TransferSubProofCount; i++ {
		offset = copyBuf(&proofBytes, offset, TransferSubProofSize, proof.SubProofs[i].Bytes())
	}
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_sum.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sum.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.C1.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.C2.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.GasFee))
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.AssetId))
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
	offset := 0
	for i := 0; i < TransferSubProofCount; i++ {
		offset, proof.SubProofs[i], err = readTransferSubProofFromBuf(proofBytes, offset)
		if err != nil {
			return nil, err
		}
	}
	offset, proof.A_sum, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_sum = readBigIntFromBuf(proofBytes, offset)
	offset, proof.C1 = readBigIntFromBuf(proofBytes, offset)
	offset, proof.C2 = readBigIntFromBuf(proofBytes, offset)
	offset, proof.GasFee = readUint64FromBuf(proofBytes, offset)
	offset, proof.AssetId = readUint32FromBuf(proofBytes, offset)
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
	offset := 0
	// A_CLDelta, A_CRDelta, A_Y1, , A_T, A_pk, A_TDivCPrime
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_CLDelta.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_CRDelta.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_Y1.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_Y2.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_T.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_pk.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_TDivCPrime.Marshal())
	// Z_r, Z_bDelta, Z_rstar1, Z_rstarSubrbar, Z_bar_r, Z_bprime, Z_sk, Z_skInv
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_r.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bDelta.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_rstar1.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_rstar2.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bstar1.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bstar2.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_rbar.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bprime.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sk.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_skInv.FillBytes(make([]byte, PointSize)))
	// C
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.CDelta))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.T.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Y.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk.Marshal())
	offset = copyBuf(&proofBytes, offset, RangeProofSize, proof.BStarRangeProof.Bytes())
	return proofBytes
}

func ParseTransferSubProofBytes(proofBytes []byte) (proof *TransferSubProof, err error) {
	if len(proofBytes) != TransferSubProofSize {
		return nil, ErrInvalidTransferSubProofSize
	}
	proof = new(TransferSubProof)
	offset := 0
	offset, proof.A_CLDelta, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_CRDelta, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_Y1, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_Y2, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_T, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_pk, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_TDivCPrime, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_r = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_bDelta = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_rstar1 = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_rstar2 = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_bstar1 = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_bstar2 = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_rbar = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_bprime = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_sk = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_skInv = readBigIntFromBuf(proofBytes, offset)
	offset, proof.C, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.CDelta, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.T, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Y, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Pk, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.BStarRangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

type TransferProofRelation struct {
	Statements []*TransferProofStatement
	R_sum      *big.Int
	GasFee     uint64
	AssetId    uint32
}

func NewTransferProofRelation(assetId uint32, fee uint64) (*TransferProofRelation, error) {
	if !validUint64(fee) {
		log.Println("[NewTransferProofRelation] err: invalid fee")
		return nil, errors.New("[NewTransferProofRelation] err: invalid fee")
	}
	return &TransferProofRelation{AssetId: assetId, GasFee: fee, R_sum: big.NewInt(0)}, nil
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
		if b == 0 && relation.GasFee > 0 {
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
