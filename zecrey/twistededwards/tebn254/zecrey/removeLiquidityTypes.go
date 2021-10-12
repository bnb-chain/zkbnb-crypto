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
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
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
	LC_Dao_A, LC_Dao_B           *ElGamalEnc
	C_uA_Delta, C_uB_Delta       *ElGamalEnc
	LC_DaoA_Delta, LC_DaoB_Delta *ElGamalEnc
	C_u_LP                       *ElGamalEnc
	C_u_LP_Delta                 *ElGamalEnc
	Pk_Dao, Pk_u                 *Point
	T_uLP                        *Point
	R_DaoA, R_DaoB               *big.Int
	R_DeltaA, R_DeltaB           *big.Int
	B_Dao_A, B_Dao_B             uint64
	B_A_Delta, B_B_Delta         uint64
	Delta_LP                     uint64
	P                            uint64
	G, H                         *Point
	AssetAId, AssetBId           uint32
}

func (proof *RemoveLiquidityProof) Bytes() []byte {
	proofBytes := make([]byte, RemoveLiquidityProofSize)
	// valid Enc
	copy(proofBytes[:PointSize], proof.A_CLPL_Delta.Marshal())
	copy(proofBytes[PointSize:PointSize*2], proof.A_CLPR_DeltaHExp_DeltaLPNeg.Marshal())
	copy(proofBytes[PointSize*2:PointSize*3], proof.Z_rDelta_LP.FillBytes(make([]byte, PointSize)))
	// Ownership
	copy(proofBytes[PointSize*3:PointSize*4], proof.A_pk_u.Marshal())
	copy(proofBytes[PointSize*4:PointSize*5], proof.A_T_uLPC_uLPRPrimeInv.Marshal())
	copy(proofBytes[PointSize*5:PointSize*6], proof.Z_sk_u.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*6:PointSize*7], proof.Z_bar_r_LP.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*7:PointSize*8], proof.Z_sk_uInv.FillBytes(make([]byte, PointSize)))
	// common inputs
	// user asset A balance enc
	LC_Dao_ABytes := proof.LC_Dao_A.Bytes()
	copy(proofBytes[PointSize*8:PointSize*10], LC_Dao_ABytes[:])
	// user asset B balance enc
	LC_Dao_BBytes := proof.LC_Dao_B.Bytes()
	copy(proofBytes[PointSize*10:PointSize*12], LC_Dao_BBytes[:])
	// user asset A&B Delta enc
	C_uA_DeltaBytes := proof.C_uA_Delta.Bytes()
	copy(proofBytes[PointSize*12:PointSize*14], C_uA_DeltaBytes[:])
	C_uB_DeltaBytes := proof.C_uB_Delta.Bytes()
	copy(proofBytes[PointSize*14:PointSize*16], C_uB_DeltaBytes[:])
	// Dao asset A&B Delta enc
	LC_DaoA_DeltaBytes := proof.LC_DaoA_Delta.Bytes()
	copy(proofBytes[PointSize*16:PointSize*18], LC_DaoA_DeltaBytes[:])
	LC_DaoB_DeltaBytes := proof.LC_DaoB_Delta.Bytes()
	copy(proofBytes[PointSize*18:PointSize*20], LC_DaoB_DeltaBytes[:])
	C_u_LPBytes := proof.C_u_LP.Bytes()
	copy(proofBytes[PointSize*20:PointSize*22], C_u_LPBytes[:])
	C_u_LP_DeltaBytes := proof.C_u_LP_Delta.Bytes()
	copy(proofBytes[PointSize*22:PointSize*24], C_u_LP_DeltaBytes[:])
	// public keys
	copy(proofBytes[PointSize*24:PointSize*25], proof.Pk_Dao.Marshal())
	copy(proofBytes[PointSize*25:PointSize*26], proof.Pk_u.Marshal())
	// random value for Delta A & B
	copy(proofBytes[PointSize*26:PointSize*27], proof.R_DaoA.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*27:PointSize*28], proof.R_DaoB.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*28:PointSize*29], proof.R_DeltaA.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*29:PointSize*30], proof.R_DeltaB.FillBytes(make([]byte, PointSize)))
	// commitment for user asset A & fee
	copy(proofBytes[PointSize*30:PointSize*31], proof.T_uLP.Marshal())
	// generators
	copy(proofBytes[PointSize*31:PointSize*32], proof.G.Marshal())
	copy(proofBytes[PointSize*32:PointSize*33], proof.H.Marshal())
	// user asset A,B,LP & DAO assets A,B
	B_Dao_ABytes := make([]byte, EightBytes)
	B_Dao_BBytes := make([]byte, EightBytes)
	B_A_DeltaBytes := make([]byte, EightBytes)
	B_B_DeltaBytes := make([]byte, EightBytes)
	Delta_LPBytes := make([]byte, EightBytes)
	PBytes := make([]byte, EightBytes)
	binary.BigEndian.PutUint64(B_Dao_ABytes, proof.B_Dao_A)
	binary.BigEndian.PutUint64(B_Dao_BBytes, proof.B_Dao_B)
	binary.BigEndian.PutUint64(B_A_DeltaBytes, proof.B_A_Delta)
	binary.BigEndian.PutUint64(B_B_DeltaBytes, proof.B_B_Delta)
	binary.BigEndian.PutUint64(Delta_LPBytes, proof.Delta_LP)
	binary.BigEndian.PutUint64(PBytes, proof.P)
	copy(proofBytes[PointSize*33:PointSize*33+EightBytes], B_Dao_ABytes)
	copy(proofBytes[PointSize*33+EightBytes:PointSize*33+EightBytes*2], B_Dao_BBytes)
	copy(proofBytes[PointSize*33+EightBytes*2:PointSize*33+EightBytes*3], B_A_DeltaBytes)
	copy(proofBytes[PointSize*33+EightBytes*3:PointSize*33+EightBytes*4], B_B_DeltaBytes)
	copy(proofBytes[PointSize*33+EightBytes*4:PointSize*33+EightBytes*5], Delta_LPBytes)
	copy(proofBytes[PointSize*33+EightBytes*5:PointSize*33+EightBytes*6], PBytes)
	// range proofs
	copy(proofBytes[PointSize*33+EightBytes*6:PointSize*33+EightBytes*6+RangeProofSize], proof.LPRangeProof.Bytes())
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
	// valid Enc
	proof.A_CLPL_Delta, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.A_CLPR_DeltaHExp_DeltaLPNeg, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.Z_rDelta_LP = new(big.Int).SetBytes(proofBytes[PointSize*2 : PointSize*3])
	// Ownership
	proof.A_pk_u, err = curve.FromBytes(proofBytes[PointSize*3 : PointSize*4])
	if err != nil {
		return nil, err
	}
	proof.A_T_uLPC_uLPRPrimeInv, err = curve.FromBytes(proofBytes[PointSize*4 : PointSize*5])
	if err != nil {
		return nil, err
	}
	proof.Z_sk_u = new(big.Int).SetBytes(proofBytes[PointSize*5 : PointSize*6])
	proof.Z_bar_r_LP = new(big.Int).SetBytes(proofBytes[PointSize*6 : PointSize*7])
	proof.Z_sk_uInv = new(big.Int).SetBytes(proofBytes[PointSize*7 : PointSize*8])
	// common inputs
	// user asset A balance enc
	proof.LC_Dao_A, err = twistedElgamal.FromBytes(proofBytes[PointSize*8 : PointSize*10])
	if err != nil {
		return nil, err
	}
	// user asset fee balance enc
	proof.LC_Dao_B, err = twistedElgamal.FromBytes(proofBytes[PointSize*10 : PointSize*12])
	if err != nil {
		return nil, err
	}
	// user asset A Delta enc
	proof.C_uA_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*12 : PointSize*14])
	if err != nil {
		return nil, err
	}
	// user asset B Delta enc
	proof.C_uB_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*14 : PointSize*16])
	if err != nil {
		return nil, err
	}
	// liquidity pool asset A,B Delta enc
	proof.LC_DaoA_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*16 : PointSize*18])
	if err != nil {
		return nil, err
	}
	proof.LC_DaoB_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*18 : PointSize*20])
	if err != nil {
		return nil, err
	}
	proof.C_u_LP, err = twistedElgamal.FromBytes(proofBytes[PointSize*20 : PointSize*22])
	if err != nil {
		return nil, err
	}
	proof.C_u_LP_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*22 : PointSize*24])
	if err != nil {
		return nil, err
	}
	// public keys
	proof.Pk_Dao, err = curve.FromBytes(proofBytes[PointSize*24 : PointSize*25])
	if err != nil {
		return nil, err
	}
	proof.Pk_u, err = curve.FromBytes(proofBytes[PointSize*25 : PointSize*26])
	if err != nil {
		return nil, err
	}
	// random value for Delta A & B
	proof.R_DaoA = new(big.Int).SetBytes(proofBytes[PointSize*26 : PointSize*27])
	proof.R_DaoB = new(big.Int).SetBytes(proofBytes[PointSize*27 : PointSize*28])
	proof.R_DeltaA = new(big.Int).SetBytes(proofBytes[PointSize*28 : PointSize*29])
	proof.R_DeltaB = new(big.Int).SetBytes(proofBytes[PointSize*29 : PointSize*30])
	// commitment for user asset A & fee
	proof.T_uLP, err = curve.FromBytes(proofBytes[PointSize*30 : PointSize*31])
	if err != nil {
		return nil, err
	}
	// generators
	proof.G, err = curve.FromBytes(proofBytes[PointSize*31 : PointSize*32])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[PointSize*32 : PointSize*33])
	if err != nil {
		return nil, err
	}
	// asset a,b,lp
	proof.B_Dao_A = binary.BigEndian.Uint64(proofBytes[PointSize*33 : PointSize*33+EightBytes])
	proof.B_Dao_B = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes : PointSize*33+EightBytes*2])
	proof.B_A_Delta = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*2 : PointSize*33+EightBytes*3])
	proof.B_B_Delta = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*3 : PointSize*33+EightBytes*4])
	proof.Delta_LP = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*4 : PointSize*33+EightBytes*5])
	proof.P = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*5 : PointSize*33+EightBytes*6])
	// range proofs
	proof.LPRangeProof, err = ctrange.FromBytes(proofBytes[PointSize*33+EightBytes*6 : PointSize*33+EightBytes*6+RangeProofSize])
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
	LC_Dao_A, LC_Dao_B           *ElGamalEnc
	C_uA_Delta, C_uB_Delta       *ElGamalEnc
	LC_DaoA_Delta, LC_DaoB_Delta *ElGamalEnc
	Pk_Dao, Pk_u                 *Point
	R_DaoA, R_DaoB               *big.Int
	R_DeltaA, R_DeltaB           *big.Int
	B_Dao_A, B_Dao_B             uint64
	B_A_Delta, B_B_Delta         uint64
	Delta_LP                     uint64
	C_u_LP                       *ElGamalEnc
	C_u_LP_Delta                 *ElGamalEnc
	P                            uint64
	G, H                         *Point
	AssetAId, AssetBId           uint32
	T_uLP                        *Point
	// private inputs
	Sk_u                *big.Int
	Bar_r_LP, R_DeltaLP *big.Int
	B_LP_Prime          uint64
	// range proof
	LPRangeProof *RangeProof
}

func NewRemoveLiquidityRelation(
	C_u_LP *ElGamalEnc,
	Pk_Dao, Pk_u *Point,
	B_LP uint64,
	Delta_LP uint64,
	B_A_Delta, B_B_Delta uint64,
	assetAId, assetBId uint32,
	Sk_u *big.Int,
) (relation *RemoveLiquidityRelation, err error) {
	if !notNullElGamal(C_u_LP) || Sk_u == nil ||
		!curve.IsInSubGroup(Pk_u) || !curve.IsInSubGroup(Pk_Dao) ||
		assetAId == assetBId ||
		B_LP < Delta_LP {
		log.Println("[NewRemoveLiquidityRelation] err: invalid params")
		return nil, errors.New("[NewRemoveLiquidityRelation] err: invalid params")
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
		C_u_LP_Delta                 *ElGamalEnc
		C_uA_Delta, C_uB_Delta       *ElGamalEnc
		LC_DaoA_Delta, LC_DaoB_Delta *ElGamalEnc
		R_DeltaA, R_DeltaB           *big.Int
		Bar_r_LP                     *big.Int
		B_LP_Prime                   uint64
		R_DeltaLP                    *big.Int
		LPRangeProof                 *RangeProof
	)
	// generate random values
	R_DeltaA = curve.RandomValue()
	R_DeltaB = curve.RandomValue()
	R_DeltaLP = curve.RandomValue()
	// compute C_uj_Delta
	C_uA_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_A_Delta)), R_DeltaA, Pk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	C_uB_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_B_Delta)), R_DeltaB, Pk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	C_u_LP_Delta, err = twistedElgamal.Enc(big.NewInt(int64(Delta_LP)), R_DeltaLP, Pk_u)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	// compute LC_Daoj_Delta
	LC_DaoA_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_A_Delta)), R_DeltaA, Pk_Dao)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	LC_DaoB_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_B_Delta)), R_DeltaB, Pk_Dao)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] err info:", err)
		return nil, err
	}
	// compute range proofs
	B_LP_Prime = B_LP - Delta_LP
	Bar_r_LP, LPRangeProof, err = proveCtRange(int64(B_LP_Prime), G, H)
	if err != nil {
		log.Println("[NewAddLiquidityRelation] invalid range proof:", err)
		return nil, err
	}
	relation = &RemoveLiquidityRelation{
		LC_Dao_A:      &ElGamalEnc{CL: curve.ZeroPoint(), CR: curve.ZeroPoint()},
		LC_Dao_B:      &ElGamalEnc{CL: curve.ZeroPoint(), CR: curve.ZeroPoint()},
		C_uA_Delta:    C_uA_Delta,
		C_uB_Delta:    C_uB_Delta,
		LC_DaoA_Delta: LC_DaoA_Delta,
		LC_DaoB_Delta: LC_DaoB_Delta,
		Pk_Dao:        Pk_Dao,
		Pk_u:          Pk_u,
		R_DaoA:        big.NewInt(0),
		R_DaoB:        big.NewInt(0),
		R_DeltaA:      R_DeltaA,
		R_DeltaB:      R_DeltaB,
		B_Dao_A:       0,
		B_Dao_B:       0,
		B_A_Delta:     B_A_Delta,
		B_B_Delta:     B_B_Delta,
		Delta_LP:      Delta_LP,
		C_u_LP:        C_u_LP,
		C_u_LP_Delta:  C_u_LP_Delta,
		P:             0,
		G:             G,
		H:             H,
		AssetAId:      assetAId,
		AssetBId:      assetBId,
		T_uLP:         new(Point).Set(LPRangeProof.A),
		Sk_u:          Sk_u,
		Bar_r_LP:      Bar_r_LP,
		R_DeltaLP:     R_DeltaLP,
		B_LP_Prime:    B_LP_Prime,
		LPRangeProof:  LPRangeProof,
	}
	return relation, nil
}
