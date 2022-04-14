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

package zecrey

import (
	"encoding/base64"
	"errors"
	"log"
	"math"
	"math/big"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

type AddLiquidityProof struct {
	// valid enc
	A_CLPL_Delta                *Point
	A_CLPR_DeltaHExp_DeltaLPNeg *Point
	Z_rDelta_LP                 *big.Int
	// ownership
	A_pk_u, A_T_uAC_uARPrimeInv, A_T_uBC_uBRPrimeInv *Point
	Z_sk_u, Z_bar_r_A, Z_bar_r_B, Z_sk_uInv          *big.Int
	// range proofs
	ARangeProof, BRangeProof *RangeProof
	// common inputs
	C_uA, C_uB                     *ElGamalEnc
	C_uA_Delta, C_uB_Delta         *ElGamalEnc
	LC_poolA_Delta, LC_poolB_Delta *ElGamalEnc
	C_LP_Delta                     *ElGamalEnc
	Pk_u, Pk_pool                  *Point
	R_DeltaA, R_DeltaB             *big.Int
	T_uA, T_uB                     *Point
	B_poolA, B_poolB               uint64
	B_A_Delta, B_B_Delta           uint64
	Delta_LP                       uint64
	// assets id
	AssetAId, AssetBId uint32
	// gas fee
	A_T_feeC_feeRPrimeInv *Point
	Z_bar_r_fee           *big.Int
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	GasFeeAssetId         uint32
	GasFee                uint64
	GasFeePrimeRangeProof *RangeProof
}

func (proof *AddLiquidityProof) Bytes() []byte {
	proofBytes := make([]byte, AddLiquidityProofSize)
	offset := 0
	// valid Enc
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_CLPL_Delta.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_CLPR_DeltaHExp_DeltaLPNeg.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_rDelta_LP.FillBytes(make([]byte, PointSize)))
	// Ownership
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_pk_u.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_T_uAC_uARPrimeInv.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_T_uBC_uBRPrimeInv.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sk_u.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bar_r_A.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bar_r_B.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sk_uInv.FillBytes(make([]byte, PointSize)))
	// common inputs
	// user asset A balance enc
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uA))
	// user asset B balance enc
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uB))
	// user asset A&B Delta enc
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uA_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uB_Delta))
	// pool asset A&B Delta enc
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.LC_poolA_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.LC_poolB_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_LP_Delta))
	// public keys
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk_pool.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk_u.Marshal())
	// random value for Delta A & B
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_DeltaA.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_DeltaB.FillBytes(make([]byte, PointSize)))
	// commitment for user asset A & fee
	offset = copyBuf(&proofBytes, offset, PointSize, proof.T_uA.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.T_uB.Marshal())
	// user asset A,B,LP & DAO assets A,B
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_poolA))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_poolB))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_A_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_B_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.Delta_LP))
	// range proofs
	offset = copyBuf(&proofBytes, offset, RangeProofSize, proof.ARangeProof.Bytes())
	offset = copyBuf(&proofBytes, offset, RangeProofSize, proof.BRangeProof.Bytes())
	// assets id
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.AssetAId))
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.AssetBId))
	// gas part
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_T_feeC_feeRPrimeInv.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bar_r_fee.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_fee))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.T_fee.Marshal())
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.GasFeeAssetId))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.GasFee))
	offset = copyBuf(&proofBytes, offset, RangeProofSize, proof.GasFeePrimeRangeProof.Bytes())
	return proofBytes
}

func (proof *AddLiquidityProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseAddLiquidityProofBytes(proofBytes []byte) (proof *AddLiquidityProof, err error) {
	if len(proofBytes) != AddLiquidityProofSize {
		log.Println("[ParseAddLiquidityProofBytes] invalid proof size")
		return nil, errors.New("[ParseAddLiquidityProofBytes] invalid proof size")
	}
	// construct new proof
	proof = new(AddLiquidityProof)
	offset := 0
	// valid Enc
	offset, proof.A_CLPL_Delta, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_CLPR_DeltaHExp_DeltaLPNeg, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_rDelta_LP = readBigIntFromBuf(proofBytes, offset)
	// Ownership
	offset, proof.A_pk_u, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_T_uAC_uARPrimeInv, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_T_uBC_uBRPrimeInv, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_sk_u = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_bar_r_A = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_bar_r_B = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_sk_uInv = readBigIntFromBuf(proofBytes, offset)
	// common inputs
	// user asset A balance enc
	offset, proof.C_uA, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// user asset fee balance enc
	offset, proof.C_uB, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// user asset A Delta enc
	offset, proof.C_uA_Delta, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// user asset B Delta enc
	offset, proof.C_uB_Delta, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// liquidity pool asset A,B Delta enc
	offset, proof.LC_poolA_Delta, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.LC_poolB_Delta, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.C_LP_Delta, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// public keys
	offset, proof.Pk_pool, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Pk_u, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// random value for Delta A & B
	offset, proof.R_DeltaA = readBigIntFromBuf(proofBytes, offset)
	offset, proof.R_DeltaB = readBigIntFromBuf(proofBytes, offset)
	// commitment for user asset A & fee
	offset, proof.T_uA, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.T_uB, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// asset a,b,lp
	offset, proof.B_poolA = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_poolB = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_A_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_B_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.Delta_LP = readUint64FromBuf(proofBytes, offset)
	// range proofs
	offset, proof.ARangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.BRangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// assets id
	offset, proof.AssetAId = readUint32FromBuf(proofBytes, offset)
	offset, proof.AssetBId = readUint32FromBuf(proofBytes, offset)
	// gas fee part
	offset, proof.A_T_feeC_feeRPrimeInv, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_bar_r_fee = readBigIntFromBuf(proofBytes, offset)
	offset, proof.C_fee, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.T_fee, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.GasFeeAssetId = readUint32FromBuf(proofBytes, offset)
	offset, proof.GasFee = readUint64FromBuf(proofBytes, offset)
	offset, proof.GasFeePrimeRangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func ParseAddLiquidityProofStr(proofStr string) (proof *AddLiquidityProof, err error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseAddLiquidityProofBytes(proofBytes)
}

/*
	AddLiquidityRelation: used to generate add liquidity proof
*/
type AddLiquidityRelation struct {
	// public inputs
	C_uA, C_uB                     *ElGamalEnc
	C_uA_Delta, C_uB_Delta         *ElGamalEnc
	LC_poolA_Delta, LC_poolB_Delta *ElGamalEnc
	C_LP_Delta                     *ElGamalEnc
	Pk_pool, Pk_u                  *Point
	R_DeltaA, R_DeltaB             *big.Int
	T_uA, T_uB                     *Point
	B_poolA, B_poolB               uint64
	B_A_Delta, B_B_Delta           uint64
	Delta_LP                       uint64
	AssetAId, AssetBId             uint32
	// private inputs
	Sk_u                   *big.Int
	Bar_r_A, Bar_r_B       *big.Int
	B_uA_prime, B_uB_prime uint64
	R_DeltaLP              *big.Int
	// range proofs
	ARangeProof, BRangeProof *RangeProof
	// gas fee
	B_fee_prime           uint64
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	Bar_r_fee             *big.Int
	GasFeeAssetId         uint32
	GasFee                uint64
	GasFeePrimeRangeProof *RangeProof
}

func NewAddLiquidityRelation(
	C_uA, C_uB *ElGamalEnc,
	Pk_pool, Pk_u *Point,
	assetAId, assetBId uint32,
	B_uA, B_uB uint64,
	B_A_Delta, B_B_Delta uint64,
	Sk_u *big.Int,
// fee part
	C_fee *ElGamalEnc, B_fee uint64, GasFeeAssetId uint32, GasFee uint64,
) (
	relation *AddLiquidityRelation, err error,
) {
	if !validUint64(B_uA) || !validUint64(B_uB) || !validUint64(B_A_Delta) || !validUint64(B_B_Delta) ||
		!notNullElGamal(C_uA) || !notNullElGamal(C_uB) || Sk_u == nil ||
		!curve.IsInSubGroup(Pk_u) || !curve.IsInSubGroup(Pk_pool) ||
		assetAId == assetBId ||
		B_uA < B_A_Delta || B_uB < B_B_Delta {
		log.Println("[NewAddLiquidityRelation] err: invalid params")
		return nil, errors.New("[NewAddLiquidityRelation] err: invalid params")
	}
	// fee check
	if !notNullElGamal(C_fee) || B_fee < GasFee {
		log.Println("[NewRemoveLiquidityRelation] err: invalid gas fee params")
		return nil, errors.New("[NewRemoveLiquidityRelation] err: invalid gas fee params")
	}
	// check original balances
	hb_A, err := twistedElgamal.RawDec(C_uA, Sk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	hb_ACheck := curve.ScalarMul(H, big.NewInt(int64(B_uA)))
	if !hb_A.Equal(hb_ACheck) {
		log.Println("[NewAddLiquidityRelation] err: invalid balance enc")
		return nil, errors.New("[NewAddLiquidityRelation] err: invalid balance enc")
	}
	hb_B, err := twistedElgamal.RawDec(C_uB, Sk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	hb_BCheck := curve.ScalarMul(H, big.NewInt(int64(B_uB)))
	if !hb_B.Equal(hb_BCheck) {
		log.Println("[NewAddLiquidityRelation] err: invalid balance enc")
		return nil, errors.New("[NewAddLiquidityRelation] err: invalid balance enc")
	}
	// define variables
	var (
		Delta_LP                       uint64
		C_LP_Delta                     *ElGamalEnc
		C_uA_Delta, C_uB_Delta         *ElGamalEnc
		LC_poolA_Delta, LC_poolB_Delta *ElGamalEnc
		R_DeltaA, R_DeltaB             *big.Int
		Bar_r_A                        = new(big.Int)
		Bar_r_B                        = new(big.Int)
		B_uA_prime, B_uB_prime         uint64
		R_DeltaLP                      *big.Int
		ARangeProof                    = new(RangeProof)
		BRangeProof                    = new(RangeProof)
		// gas fee part
		B_fee_prime           uint64
		Bar_r_fee             = new(big.Int)
		GasFeePrimeRangeProof = new(RangeProof)
	)
	// compute delta LP = \sqrt{b_A^{\Delta} b_B^{\Delta}}
	Delta_LP = uint64(math.Floor(math.Sqrt(float64(B_A_Delta) * float64(B_B_Delta))))
	// generate random values
	R_DeltaA = curve.RandomValue()
	R_DeltaB = curve.RandomValue()
	R_DeltaLP = curve.RandomValue()
	// compute C_uj_Delta
	C_uA_Delta, err = twistedElgamal.EncNeg(big.NewInt(int64(B_A_Delta)), R_DeltaA, Pk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	C_uB_Delta, err = twistedElgamal.EncNeg(big.NewInt(int64(B_B_Delta)), R_DeltaB, Pk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	C_LP_Delta, err = twistedElgamal.Enc(big.NewInt(int64(Delta_LP)), R_DeltaLP, Pk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	// compute LC_poolj_Delta
	LC_poolA_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_A_Delta)), R_DeltaA, Pk_pool)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	LC_poolB_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_B_Delta)), R_DeltaB, Pk_pool)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	// gas fee part
	if GasFeeAssetId == assetAId {
		// compute range proofs
		B_uA_prime = B_uA - B_A_Delta - GasFee
		B_uB_prime = B_uB - B_B_Delta
		var (
			addLiquidityRangeCount = 2
			addLiquidityRangeChan  = make(chan int, addLiquidityRangeCount)
		)
		go proveCtRangeRoutine(int64(B_uA_prime), G, H, Bar_r_A, ARangeProof, addLiquidityRangeChan)
		go proveCtRangeRoutine(int64(B_uB_prime), G, H, Bar_r_B, BRangeProof, addLiquidityRangeChan)
		for i := 0; i < addLiquidityRangeCount; i++ {
			val := <-addLiquidityRangeChan
			if val == ErrCode {
				log.Println("[NewAddLiquidityRelation] invalid range proof")
				return nil, errors.New("[NewAddLiquidityRelation] invalid range proof")
			}
		}
		// gas part
		B_fee_prime = B_uA_prime
		Bar_r_fee.Set(Bar_r_A)
		GasFeePrimeRangeProof = ARangeProof
	} else if GasFeeAssetId == assetBId {
		// compute range proofs
		B_uA_prime = B_uA - B_A_Delta
		B_uB_prime = B_uB - B_B_Delta - GasFee
		var (
			addLiquidityRangeCount = 2
			addLiquidityRangeChan  = make(chan int, addLiquidityRangeCount)
		)
		go proveCtRangeRoutine(int64(B_uA_prime), G, H, Bar_r_A, ARangeProof, addLiquidityRangeChan)
		go proveCtRangeRoutine(int64(B_uB_prime), G, H, Bar_r_B, BRangeProof, addLiquidityRangeChan)
		for i := 0; i < addLiquidityRangeCount; i++ {
			val := <-addLiquidityRangeChan
			if val == ErrCode {
				log.Println("[NewAddLiquidityRelation] invalid range proof")
				return nil, errors.New("[NewAddLiquidityRelation] invalid range proof")
			}
		}
		// gas part
		B_fee_prime = B_uB_prime
		Bar_r_fee.Set(Bar_r_B)
		GasFeePrimeRangeProof = BRangeProof
	} else {
		// compute B_uA_prime
		B_uA_prime = B_uA - B_A_Delta
		B_uB_prime = B_uB - B_B_Delta
		B_fee_prime = B_fee - GasFee
		var (
			addLiquidityRangeCount = 3
			addLiquidityRangeChan  = make(chan int, addLiquidityRangeCount)
		)
		go proveCtRangeRoutine(int64(B_uA_prime), G, H, Bar_r_A, ARangeProof, addLiquidityRangeChan)
		go proveCtRangeRoutine(int64(B_uB_prime), G, H, Bar_r_B, BRangeProof, addLiquidityRangeChan)
		go proveCtRangeRoutine(int64(B_fee_prime), G, H, Bar_r_fee, GasFeePrimeRangeProof, addLiquidityRangeChan)
		for i := 0; i < addLiquidityRangeCount; i++ {
			val := <-addLiquidityRangeChan
			if val == ErrCode {
				log.Println("[NewAddLiquidityRelation] invalid range proof")
				return nil, errors.New("[NewAddLiquidityRelation] invalid range proof")
			}
		}
	}
	// construct relation
	relation = &AddLiquidityRelation{
		C_uA:                  C_uA,
		C_uB:                  C_uB,
		C_uA_Delta:            C_uA_Delta,
		C_uB_Delta:            C_uB_Delta,
		LC_poolA_Delta:        LC_poolA_Delta,
		LC_poolB_Delta:        LC_poolB_Delta,
		C_LP_Delta:            C_LP_Delta,
		Pk_pool:               Pk_pool,
		Pk_u:                  Pk_u,
		R_DeltaA:              R_DeltaA,
		R_DeltaB:              R_DeltaB,
		T_uA:                  new(Point).Set(ARangeProof.A),
		T_uB:                  new(Point).Set(BRangeProof.A),
		B_poolA:               0,
		B_poolB:               0,
		B_A_Delta:             B_A_Delta,
		B_B_Delta:             B_B_Delta,
		Delta_LP:              Delta_LP,
		AssetAId:              assetAId,
		AssetBId:              assetBId,
		Sk_u:                  Sk_u,
		Bar_r_A:               Bar_r_A,
		Bar_r_B:               Bar_r_B,
		B_uA_prime:            B_uA_prime,
		B_uB_prime:            B_uB_prime,
		R_DeltaLP:             R_DeltaLP,
		ARangeProof:           ARangeProof,
		BRangeProof:           BRangeProof,
		B_fee_prime:           B_fee_prime,
		C_fee:                 C_fee,
		T_fee:                 new(Point).Set(GasFeePrimeRangeProof.A),
		Bar_r_fee:             Bar_r_fee,
		GasFeeAssetId:         GasFeeAssetId,
		GasFee:                GasFee,
		GasFeePrimeRangeProof: GasFeePrimeRangeProof,
	}
	return relation, nil
}
