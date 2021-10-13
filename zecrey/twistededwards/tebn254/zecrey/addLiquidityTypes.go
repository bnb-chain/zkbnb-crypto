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
	"math"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
)

const (
	addLiquidityRangeProofCount = 2
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
	C_uA, C_uB                   *ElGamalEnc
	C_uA_Delta, C_uB_Delta       *ElGamalEnc
	LC_DaoA_Delta, LC_DaoB_Delta *ElGamalEnc
	C_LP_Delta                   *ElGamalEnc
	Pk_u, Pk_Dao                 *Point
	R_DeltaA, R_DeltaB           *big.Int
	T_uA, T_uB                   *Point
	B_DaoA, B_DaoB               uint64
	B_A_Delta, B_B_Delta         uint64
	Delta_LP                     uint64
	G, H                         *Point
}

func (proof *AddLiquidityProof) Bytes() []byte {
	proofBytes := make([]byte, AddLiquidityProofSize)
	// valid Enc
	copy(proofBytes[:PointSize], proof.A_CLPL_Delta.Marshal())
	copy(proofBytes[PointSize:PointSize*2], proof.A_CLPR_DeltaHExp_DeltaLPNeg.Marshal())
	copy(proofBytes[PointSize*2:PointSize*3], proof.Z_rDelta_LP.FillBytes(make([]byte, PointSize)))
	// Ownership
	copy(proofBytes[PointSize*3:PointSize*4], proof.A_pk_u.Marshal())
	copy(proofBytes[PointSize*4:PointSize*5], proof.A_T_uAC_uARPrimeInv.Marshal())
	copy(proofBytes[PointSize*5:PointSize*6], proof.A_T_uBC_uBRPrimeInv.Marshal())
	copy(proofBytes[PointSize*6:PointSize*7], proof.Z_sk_u.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*7:PointSize*8], proof.Z_bar_r_A.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*8:PointSize*9], proof.Z_bar_r_B.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*9:PointSize*10], proof.Z_sk_uInv.FillBytes(make([]byte, PointSize)))
	// common inputs
	// user asset A balance enc
	C_uABytes := proof.C_uA.Bytes()
	copy(proofBytes[PointSize*10:PointSize*12], C_uABytes[:])
	// user asset B balance enc
	C_uBBytes := proof.C_uB.Bytes()
	copy(proofBytes[PointSize*12:PointSize*14], C_uBBytes[:])
	// user asset A&B Delta enc
	C_uA_DeltaBytes := proof.C_uA_Delta.Bytes()
	copy(proofBytes[PointSize*14:PointSize*16], C_uA_DeltaBytes[:])
	C_uB_DeltaBytes := proof.C_uB_Delta.Bytes()
	copy(proofBytes[PointSize*16:PointSize*18], C_uB_DeltaBytes[:])
	// Dao asset A&B Delta enc
	LC_DaoA_DeltaBytes := proof.LC_DaoA_Delta.Bytes()
	copy(proofBytes[PointSize*18:PointSize*20], LC_DaoA_DeltaBytes[:])
	LC_DaoB_DeltaBytes := proof.LC_DaoB_Delta.Bytes()
	copy(proofBytes[PointSize*20:PointSize*22], LC_DaoB_DeltaBytes[:])
	C_LP_DeltaBytes := proof.C_LP_Delta.Bytes()
	copy(proofBytes[PointSize*22:PointSize*24], C_LP_DeltaBytes[:])
	// public keys
	copy(proofBytes[PointSize*24:PointSize*25], proof.Pk_Dao.Marshal())
	copy(proofBytes[PointSize*25:PointSize*26], proof.Pk_u.Marshal())
	// random value for Delta A & B
	copy(proofBytes[PointSize*26:PointSize*27], proof.R_DeltaA.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*27:PointSize*28], proof.R_DeltaB.FillBytes(make([]byte, PointSize)))
	// commitment for user asset A & fee
	copy(proofBytes[PointSize*28:PointSize*29], proof.T_uA.Marshal())
	copy(proofBytes[PointSize*29:PointSize*30], proof.T_uB.Marshal())
	// generators
	copy(proofBytes[PointSize*30:PointSize*31], proof.G.Marshal())
	copy(proofBytes[PointSize*31:PointSize*32], proof.H.Marshal())
	// user asset A,B,LP & DAO assets A,B
	B_DaoABytes := make([]byte, EightBytes)
	B_DaoBBytes := make([]byte, EightBytes)
	B_A_DeltaBytes := make([]byte, EightBytes)
	B_B_DeltaBytes := make([]byte, EightBytes)
	Delta_LPBytes := make([]byte, EightBytes)
	binary.BigEndian.PutUint64(B_DaoABytes, proof.B_DaoA)
	binary.BigEndian.PutUint64(B_DaoBBytes, proof.B_DaoB)
	binary.BigEndian.PutUint64(B_A_DeltaBytes, proof.B_A_Delta)
	binary.BigEndian.PutUint64(B_B_DeltaBytes, proof.B_B_Delta)
	binary.BigEndian.PutUint64(Delta_LPBytes, proof.Delta_LP)
	copy(proofBytes[PointSize*32:PointSize*32+EightBytes], B_DaoABytes)
	copy(proofBytes[PointSize*32+EightBytes:PointSize*32+EightBytes*2], B_DaoBBytes)
	copy(proofBytes[PointSize*32+EightBytes*2:PointSize*32+EightBytes*3], B_A_DeltaBytes)
	copy(proofBytes[PointSize*32+EightBytes*3:PointSize*32+EightBytes*4], B_B_DeltaBytes)
	copy(proofBytes[PointSize*32+EightBytes*4:PointSize*32+EightBytes*5], Delta_LPBytes)
	// range proofs
	copy(proofBytes[PointSize*32+EightBytes*5:PointSize*32+EightBytes*5+RangeProofSize], proof.ARangeProof.Bytes())
	copy(proofBytes[PointSize*32+EightBytes*5+RangeProofSize:PointSize*32+EightBytes*5+RangeProofSize*2], proof.BRangeProof.Bytes())
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
	proof.A_T_uAC_uARPrimeInv, err = curve.FromBytes(proofBytes[PointSize*4 : PointSize*5])
	if err != nil {
		return nil, err
	}
	proof.A_T_uBC_uBRPrimeInv, err = curve.FromBytes(proofBytes[PointSize*5 : PointSize*6])
	if err != nil {
		return nil, err
	}
	proof.Z_sk_u = new(big.Int).SetBytes(proofBytes[PointSize*6 : PointSize*7])
	proof.Z_bar_r_A = new(big.Int).SetBytes(proofBytes[PointSize*7 : PointSize*8])
	proof.Z_bar_r_B = new(big.Int).SetBytes(proofBytes[PointSize*8 : PointSize*9])
	proof.Z_sk_uInv = new(big.Int).SetBytes(proofBytes[PointSize*9 : PointSize*10])
	// common inputs
	// user asset A balance enc
	proof.C_uA, err = twistedElgamal.FromBytes(proofBytes[PointSize*10 : PointSize*12])
	if err != nil {
		return nil, err
	}
	// user asset fee balance enc
	proof.C_uB, err = twistedElgamal.FromBytes(proofBytes[PointSize*12 : PointSize*14])
	if err != nil {
		return nil, err
	}
	// user asset A Delta enc
	proof.C_uA_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*14 : PointSize*16])
	if err != nil {
		return nil, err
	}
	// user asset B Delta enc
	proof.C_uB_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*16 : PointSize*18])
	if err != nil {
		return nil, err
	}
	// liquidity pool asset A,B Delta enc
	proof.LC_DaoA_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*18 : PointSize*20])
	if err != nil {
		return nil, err
	}
	proof.LC_DaoB_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*20 : PointSize*22])
	if err != nil {
		return nil, err
	}
	proof.C_LP_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*22 : PointSize*24])
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
	proof.R_DeltaA = new(big.Int).SetBytes(proofBytes[PointSize*26 : PointSize*27])
	proof.R_DeltaB = new(big.Int).SetBytes(proofBytes[PointSize*27 : PointSize*28])
	// commitment for user asset A & fee
	proof.T_uA, err = curve.FromBytes(proofBytes[PointSize*28 : PointSize*29])
	if err != nil {
		return nil, err
	}
	proof.T_uB, err = curve.FromBytes(proofBytes[PointSize*29 : PointSize*30])
	if err != nil {
		return nil, err
	}
	// generators
	proof.G, err = curve.FromBytes(proofBytes[PointSize*30 : PointSize*31])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[PointSize*31 : PointSize*32])
	if err != nil {
		return nil, err
	}
	// asset a,b,lp
	proof.B_DaoA = binary.BigEndian.Uint64(proofBytes[PointSize*32 : PointSize*32+EightBytes])
	proof.B_DaoB = binary.BigEndian.Uint64(proofBytes[PointSize*32+EightBytes : PointSize*32+EightBytes*2])
	proof.B_A_Delta = binary.BigEndian.Uint64(proofBytes[PointSize*32+EightBytes*2 : PointSize*32+EightBytes*3])
	proof.B_B_Delta = binary.BigEndian.Uint64(proofBytes[PointSize*32+EightBytes*3 : PointSize*32+EightBytes*4])
	proof.Delta_LP = binary.BigEndian.Uint64(proofBytes[PointSize*32+EightBytes*4 : PointSize*32+EightBytes*5])
	// range proofs
	proof.ARangeProof, err = ctrange.FromBytes(proofBytes[PointSize*32+EightBytes*5 : PointSize*32+EightBytes*5+RangeProofSize])
	if err != nil {
		return nil, err
	}
	proof.BRangeProof, err = ctrange.FromBytes(proofBytes[PointSize*32+EightBytes*5+RangeProofSize : PointSize*32+EightBytes*5+RangeProofSize*2])
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
	C_uA, C_uB                   *ElGamalEnc
	C_uA_Delta, C_uB_Delta       *ElGamalEnc
	LC_DaoA_Delta, LC_DaoB_Delta *ElGamalEnc
	C_LP_Delta                   *ElGamalEnc
	Pk_Dao, Pk_u                 *Point
	R_DeltaA, R_DeltaB           *big.Int
	T_uA, T_uB                   *Point
	B_DaoA, B_DaoB               uint64
	B_A_Delta, B_B_Delta         uint64
	Delta_LP                     uint64
	G, H                         *Point
	AssetAId, AssetBId           uint32
	// private inputs
	Sk_u                   *big.Int
	Bar_r_A, Bar_r_B       *big.Int
	B_uA_Prime, B_uB_Prime uint64
	R_DeltaLP              *big.Int
	// range proofs
	ARangeProof, BRangeProof *RangeProof
}

func NewAddLiquidityRelation(
	C_uA, C_uB *ElGamalEnc,
	Pk_Dao, Pk_u *Point,
	assetAId, assetBId uint32,
	B_uA, B_uB uint64,
	B_A_Delta, B_B_Delta uint64,
	Sk_u *big.Int,
) (
	relation *AddLiquidityRelation, err error,
) {
	if !validUint64(B_uA) || !validUint64(B_uB) || !validUint64(B_A_Delta) || !validUint64(B_B_Delta) ||
		!notNullElGamal(C_uA) || !notNullElGamal(C_uB) || Sk_u == nil ||
		!curve.IsInSubGroup(Pk_u) || !curve.IsInSubGroup(Pk_Dao) ||
		assetAId == assetBId ||
		B_uA < B_A_Delta || B_uB < B_B_Delta {
		log.Println("[NewAddLiquidityRelation] err: invalid params")
		return nil, errors.New("[NewAddLiquidityRelation] err: invalid params")
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
		Delta_LP                     uint64
		C_LP_Delta                   *ElGamalEnc
		C_uA_Delta, C_uB_Delta       *ElGamalEnc
		LC_DaoA_Delta, LC_DaoB_Delta *ElGamalEnc
		R_DeltaA, R_DeltaB           *big.Int
		Bar_r_A                      = new(big.Int)
		Bar_r_B                      = new(big.Int)
		B_uA_Prime, B_uB_Prime       uint64
		R_DeltaLP                    *big.Int
		ARangeProof                  = new(RangeProof)
		BRangeProof                  = new(RangeProof)
		addLiquidityRangeChan        = make(chan int, addLiquidityRangeProofCount)
	)
	// compute delta LP = \sqrt{b_A^{\Delta} b_B^{\Delta}}
	Delta_LP = uint64(math.Floor(math.Sqrt(float64(B_A_Delta) * float64(B_B_Delta))))
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
	C_LP_Delta, err = twistedElgamal.Enc(big.NewInt(int64(Delta_LP)), R_DeltaLP, Pk_u)
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
	B_uA_Prime = B_uA - B_A_Delta
	B_uB_Prime = B_uB - B_B_Delta
	go proveCtRangeRoutine(int64(B_uA_Prime), G, H, Bar_r_A, ARangeProof, addLiquidityRangeChan)
	go proveCtRangeRoutine(int64(B_uB_Prime), G, H, Bar_r_B, BRangeProof, addLiquidityRangeChan)
	for i := 0; i < addLiquidityRangeProofCount; i++ {
		val := <-addLiquidityRangeChan
		if val == ErrCode {
			log.Println("[NewAddLiquidityRelation] invalid range proof")
			return nil, errors.New("[NewAddLiquidityRelation] invalid range proof")
		}
	}
	// construct relation
	relation = &AddLiquidityRelation{
		C_uA:          C_uA,
		C_uB:          C_uB,
		C_uA_Delta:    C_uA_Delta,
		C_uB_Delta:    C_uB_Delta,
		LC_DaoA_Delta: LC_DaoA_Delta,
		LC_DaoB_Delta: LC_DaoB_Delta,
		C_LP_Delta:    C_LP_Delta,
		Pk_u:          Pk_u,
		Pk_Dao:        Pk_Dao,
		R_DeltaA:      R_DeltaA,
		R_DeltaB:      R_DeltaB,
		T_uA:          new(Point).Set(ARangeProof.A),
		T_uB:          new(Point).Set(BRangeProof.A),
		B_A_Delta:     B_A_Delta,
		B_B_Delta:     B_B_Delta,
		Delta_LP:      Delta_LP,
		G:             G,
		H:             H,
		AssetAId:      assetAId,
		AssetBId:      assetBId,
		Sk_u:          Sk_u,
		Bar_r_A:       Bar_r_A,
		Bar_r_B:       Bar_r_B,
		B_uA_Prime:    B_uA_Prime,
		B_uB_Prime:    B_uB_Prime,
		R_DeltaLP:     R_DeltaLP,
		ARangeProof:   ARangeProof,
		BRangeProof:   BRangeProof,
	}
	return relation, nil
}
