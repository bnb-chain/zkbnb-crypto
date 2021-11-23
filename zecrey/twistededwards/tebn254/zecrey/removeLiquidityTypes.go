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
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

type RemoveLiquidityProof struct {
	// valid enc
	A_CLPL_Delta                *Point
	A_CLPR_DeltaHExp_DeltaLPNeg *Point
	Z_rDelta_LP                 *big.Int
	// ownership
	A_pk_u, A_T_uLPC_uLPRPrimeInv *Point
	Z_sk_u, Z_bar_r_LP, Z_sk_uInv *big.Int
	// range proofs
	LPRangeProof *RangeProof
	// common inputs
	LC_pool_A, LC_pool_B           *ElGamalEnc
	C_uA_Delta, C_uB_Delta         *ElGamalEnc
	LC_poolA_Delta, LC_poolB_Delta *ElGamalEnc
	C_u_LP                         *ElGamalEnc
	C_u_LP_Delta                   *ElGamalEnc
	Pk_pool, Pk_u                  *Point
	T_uLP                          *Point
	R_poolA, R_poolB               *big.Int
	R_DeltaA, R_DeltaB             *big.Int
	B_pool_A, B_pool_B             uint64
	B_A_Delta, B_B_Delta           uint64
	MinB_A_Delta, MinB_B_Delta     uint64
	Delta_LP                       uint64
	P                              uint64
	AssetAId, AssetBId             uint32
	// gas fee
	A_T_feeC_feeRPrimeInv *Point
	Z_bar_r_fee           *big.Int
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	GasFeeAssetId         uint32
	GasFee                uint64
	GasFeePrimeRangeProof *RangeProof
}

func (proof *RemoveLiquidityProof) Bytes() []byte {
	proofBytes := make([]byte, RemoveLiquidityProofSize)
	offset := 0
	// valid Enc
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_CLPL_Delta.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_CLPR_DeltaHExp_DeltaLPNeg.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_rDelta_LP.FillBytes(make([]byte, PointSize)))
	// Ownership
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_pk_u.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_T_uLPC_uLPRPrimeInv.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sk_u.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bar_r_LP.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sk_uInv.FillBytes(make([]byte, PointSize)))
	// common inputs
	// user asset A balance enc
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.LC_pool_A))
	// user asset B balance enc
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.LC_pool_B))
	// user asset A&B Delta enc
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uA_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uB_Delta))
	// pool asset A&B Delta enc
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.LC_poolA_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.LC_poolB_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_u_LP))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_u_LP_Delta))
	// public keys
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk_pool.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk_u.Marshal())
	// random value for Delta A & B
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_poolA.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_poolB.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_DeltaA.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_DeltaB.FillBytes(make([]byte, PointSize)))
	// commitment for user asset A & fee
	offset = copyBuf(&proofBytes, offset, PointSize, proof.T_uLP.Marshal())
	// user asset A,B,LP & DAO assets A,B
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_pool_A))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_pool_B))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_A_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_B_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.MinB_A_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.MinB_B_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.Delta_LP))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.P))
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.AssetAId))
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.AssetBId))
	// range proofs
	offset = copyBuf(&proofBytes, offset, RangeProofSize, proof.LPRangeProof.Bytes())
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

func (proof *RemoveLiquidityProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseRemoveLiquidityProofBytes(proofBytes []byte) (proof *RemoveLiquidityProof, err error) {
	if len(proofBytes) != RemoveLiquidityProofSize {
		log.Println("[ParseRemoveLiquidityProofBytes] invalid proof size")
		return nil, errors.New("[ParseRemoveLiquidityProofBytes] invalid proof size")
	}
	// construct new proof
	proof = new(RemoveLiquidityProof)
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
	offset, proof.A_T_uLPC_uLPRPrimeInv, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_sk_u = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_bar_r_LP = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_sk_uInv = readBigIntFromBuf(proofBytes, offset)
	// common inputs
	// user asset A balance enc
	offset, proof.LC_pool_A, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// user asset fee balance enc
	offset, proof.LC_pool_B, err = readElGamalEncFromBuf(proofBytes, offset)
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
	offset, proof.C_u_LP, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.C_u_LP_Delta, err = readElGamalEncFromBuf(proofBytes, offset)
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
	offset, proof.R_poolA = readBigIntFromBuf(proofBytes, offset)
	offset, proof.R_poolB = readBigIntFromBuf(proofBytes, offset)
	offset, proof.R_DeltaA = readBigIntFromBuf(proofBytes, offset)
	offset, proof.R_DeltaB = readBigIntFromBuf(proofBytes, offset)
	// commitment for user asset A & fee
	offset, proof.T_uLP, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// asset a,b,lp
	offset, proof.B_pool_A = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_pool_B = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_A_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_B_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.MinB_A_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.MinB_B_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.Delta_LP = readUint64FromBuf(proofBytes, offset)
	offset, proof.P = readUint64FromBuf(proofBytes, offset)
	offset, proof.AssetAId = readUint32FromBuf(proofBytes, offset)
	offset, proof.AssetBId = readUint32FromBuf(proofBytes, offset)
	// range proofs
	offset, proof.LPRangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
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

func ParseRemoveLiquidityProofStr(proofStr string) (proof *RemoveLiquidityProof, err error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseRemoveLiquidityProofBytes(proofBytes)
}

type RemoveLiquidityRelation struct {
	// public inputs
	LC_pool_A, LC_pool_B           *ElGamalEnc
	C_uA_Delta, C_uB_Delta         *ElGamalEnc
	LC_poolA_Delta, LC_poolB_Delta *ElGamalEnc
	Pk_pool, Pk_u                  *Point
	R_poolA, R_poolB               *big.Int
	R_DeltaA, R_DeltaB             *big.Int
	B_pool_A, B_pool_B             uint64
	B_A_Delta, B_B_Delta           uint64
	MinB_A_Delta, MinB_B_Delta     uint64
	Delta_LP                       uint64
	C_u_LP                         *ElGamalEnc
	C_u_LP_Delta                   *ElGamalEnc
	P                              uint64
	AssetAId, AssetBId             uint32
	T_uLP                          *Point
	// private inputs
	Sk_u                *big.Int
	Bar_r_LP, R_DeltaLP *big.Int
	B_LP_Prime          uint64
	// range proof
	LPRangeProof *RangeProof
	// gas fee
	B_fee_prime           uint64
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	Bar_r_fee             *big.Int
	GasFeeAssetId         uint32
	GasFee                uint64
	GasFeePrimeRangeProof *RangeProof
}

func NewRemoveLiquidityRelation(
	C_u_LP *ElGamalEnc,
	Pk_u *Point,
	B_LP uint64,
	Delta_LP uint64,
	MinB_A_Delta, MinB_B_Delta uint64,
	assetAId, assetBId uint32,
	Sk_u *big.Int,
	// fee part
	C_fee *ElGamalEnc, B_fee uint64, GasFeeAssetId uint32, GasFee uint64,
) (relation *RemoveLiquidityRelation, err error) {
	if !validUint64(B_LP) || !validUint64(Delta_LP) ||
		!notNullElGamal(C_u_LP) || Sk_u == nil ||
		!curve.IsInSubGroup(Pk_u) ||
		assetAId == assetBId ||
		B_LP < Delta_LP {
		log.Println("[NewRemoveLiquidityRelation] err: invalid params")
		return nil, errors.New("[NewRemoveLiquidityRelation] err: invalid params")
	}
	// fee check
	if !notNullElGamal(C_fee) || B_fee < GasFee {
		log.Println("[NewRemoveLiquidityRelation] err: invalid gas fee params")
		return nil, errors.New("[NewRemoveLiquidityRelation] err: invalid gas fee params")
	}
	// check original balances
	hb_LP, err := twistedElgamal.RawDec(C_u_LP, Sk_u)
	if err != nil {
		log.Println("[NewRemoveLiquidityRelation] err info:", err)
		return nil, err
	}
	hb_LPCheck := curve.ScalarMul(H, big.NewInt(int64(B_LP)))
	if !hb_LP.Equal(hb_LPCheck) {
		log.Println("[NewRemoveLiquidityRelation] err: invalid balance enc")
		return nil, errors.New("[NewRemoveLiquidityRelation] err: invalid balance enc")
	}
	// define variables
	var (
		C_u_LP_Delta       *ElGamalEnc
		R_DeltaA, R_DeltaB *big.Int
		Bar_r_LP           = new(big.Int)
		B_LP_Prime         uint64
		R_DeltaLP          *big.Int
		LPRangeProof       = new(RangeProof)
		// gas fee part
		B_fee_prime           uint64
		Bar_r_fee             = new(big.Int)
		GasFeePrimeRangeProof = new(RangeProof)
	)
	// generate random values
	R_DeltaA = curve.RandomValue()
	R_DeltaB = curve.RandomValue()
	R_DeltaLP = curve.RandomValue()
	// compute C_uj_Delta
	C_u_LP_Delta, err = twistedElgamal.EncNeg(big.NewInt(int64(Delta_LP)), R_DeltaLP, Pk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	// compute range proofs
	B_LP_Prime = B_LP - Delta_LP
	// gas fee part
	B_fee_prime = B_fee - GasFee
	var (
		removeLiquidityRangeCount = 2
		removeLiquidityRangeChan  = make(chan int, removeLiquidityRangeCount)
	)
	// prove b_u_A' is greater than 0
	go proveCtRangeRoutine(int64(B_LP_Prime), G, H, Bar_r_LP, LPRangeProof, removeLiquidityRangeChan)
	// gas part
	go proveCtRangeRoutine(int64(B_fee_prime), G, H, Bar_r_fee, GasFeePrimeRangeProof, removeLiquidityRangeChan)
	for i := 0; i < removeLiquidityRangeCount; i++ {
		val := <-removeLiquidityRangeChan
		if val == ErrCode {
			return nil, errors.New("[NewSwapRelation] range proof works error")
		}
	}
	relation = &RemoveLiquidityRelation{
		LC_pool_A:             zeroElGamal(),
		LC_pool_B:             zeroElGamal(),
		C_uA_Delta:            zeroElGamal(),
		C_uB_Delta:            zeroElGamal(),
		LC_poolA_Delta:        zeroElGamal(),
		LC_poolB_Delta:        zeroElGamal(),
		Pk_pool:               curve.ZeroPoint(),
		Pk_u:                  Pk_u,
		R_poolA:               big.NewInt(0),
		R_poolB:               big.NewInt(0),
		R_DeltaA:              R_DeltaA,
		R_DeltaB:              R_DeltaB,
		B_pool_A:              0,
		B_pool_B:              0,
		B_A_Delta:             0,
		B_B_Delta:             0,
		Delta_LP:              Delta_LP,
		C_u_LP:                C_u_LP,
		C_u_LP_Delta:          C_u_LP_Delta,
		P:                     0,
		AssetAId:              assetAId,
		AssetBId:              assetBId,
		MinB_A_Delta:          MinB_A_Delta,
		MinB_B_Delta:          MinB_B_Delta,
		T_uLP:                 new(Point).Set(LPRangeProof.A),
		Sk_u:                  Sk_u,
		Bar_r_LP:              Bar_r_LP,
		R_DeltaLP:             R_DeltaLP,
		B_LP_Prime:            B_LP_Prime,
		LPRangeProof:          LPRangeProof,
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
