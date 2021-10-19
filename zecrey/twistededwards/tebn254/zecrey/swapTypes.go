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

const (
	swapRangeProofCount = 2
)

func (proof *SwapProof) Bytes() []byte {
	proofBytes := make([]byte, SwapProofSize)
	// valid Enc
	copy(proofBytes[:PointSize], proof.A_C_ufeeL_Delta.Marshal())
	copy(proofBytes[PointSize:PointSize*2], proof.A_CufeeR_DeltaHExpb_fee_DeltaInv.Marshal())
	copy(proofBytes[PointSize*2:PointSize*3], proof.Z_r_Deltafee.FillBytes(make([]byte, PointSize)))
	// Ownership
	copy(proofBytes[PointSize*3:PointSize*4], proof.A_pk_u.Marshal())
	copy(proofBytes[PointSize*4:PointSize*5], proof.A_T_uAC_uARPrimeInv.Marshal())
	copy(proofBytes[PointSize*5:PointSize*6], proof.A_T_ufeeC_ufeeRPrimeInv.Marshal())
	copy(proofBytes[PointSize*6:PointSize*7], proof.Z_sk_u.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*7:PointSize*8], proof.Z_bar_r_A.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*8:PointSize*9], proof.Z_bar_r_fee.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*9:PointSize*10], proof.Z_sk_uInv.FillBytes(make([]byte, PointSize)))
	// common inputs
	// user asset A balance enc
	C_uABytes := proof.C_uA.Bytes()
	copy(proofBytes[PointSize*10:PointSize*12], C_uABytes[:])
	// user asset fee balance enc
	C_ufeeBytes := proof.C_ufee.Bytes()
	copy(proofBytes[PointSize*12:PointSize*14], C_ufeeBytes[:])
	// user asset fee Delta enc
	C_ufee_DeltaBytes := proof.C_ufee_Delta.Bytes()
	copy(proofBytes[PointSize*14:PointSize*16], C_ufee_DeltaBytes[:])
	// user asset A,B Delta enc
	C_uA_DeltaBytes := proof.C_uA_Delta.Bytes()
	C_uB_DeltaBytes := proof.C_uB_Delta.Bytes()
	copy(proofBytes[PointSize*16:PointSize*18], C_uA_DeltaBytes[:])
	copy(proofBytes[PointSize*18:PointSize*20], C_uB_DeltaBytes[:])
	// liquidity pool asset A,B Delta enc
	LC_DaoA_DeltaBytes := proof.LC_DaoA_Delta.Bytes()
	LC_DaoB_DeltaBytes := proof.LC_DaoB_Delta.Bytes()
	copy(proofBytes[PointSize*20:PointSize*22], LC_DaoA_DeltaBytes[:])
	copy(proofBytes[PointSize*22:PointSize*24], LC_DaoB_DeltaBytes[:])
	// public keys
	copy(proofBytes[PointSize*24:PointSize*25], proof.Pk_Dao.Marshal())
	copy(proofBytes[PointSize*25:PointSize*26], proof.Pk_u.Marshal())
	// random value for Delta A & B
	copy(proofBytes[PointSize*26:PointSize*27], proof.R_DeltaA.FillBytes(make([]byte, PointSize)))
	copy(proofBytes[PointSize*27:PointSize*28], proof.R_DeltaB.FillBytes(make([]byte, PointSize)))
	// commitment for user asset A & fee
	copy(proofBytes[PointSize*28:PointSize*29], proof.T_uA.Marshal())
	copy(proofBytes[PointSize*29:PointSize*30], proof.T_ufee.Marshal())
	// liquidity pool asset B balance
	LC_DaoBBytes := proof.LC_DaoB.Bytes()
	copy(proofBytes[PointSize*30:PointSize*32], LC_DaoBBytes[:])
	// random value for dao liquidity asset B
	copy(proofBytes[PointSize*32:PointSize*33], proof.R_DaoB.FillBytes(make([]byte, PointSize)))
	// asset A,B,fee Delta & dao liquidity asset B balance
	B_A_DeltaBytes := make([]byte, EightBytes)
	B_B_DeltaBytes := make([]byte, EightBytes)
	B_fee_DeltaBytes := make([]byte, EightBytes)
	B_DaoABytes := make([]byte, EightBytes)
	B_DaoBBytes := make([]byte, EightBytes)
	binary.BigEndian.PutUint64(B_A_DeltaBytes, proof.B_A_Delta)
	binary.BigEndian.PutUint64(B_B_DeltaBytes, proof.B_B_Delta)
	binary.BigEndian.PutUint64(B_fee_DeltaBytes, proof.B_fee_Delta)
	binary.BigEndian.PutUint64(B_DaoABytes, proof.B_DaoA)
	binary.BigEndian.PutUint64(B_DaoBBytes, proof.B_DaoB)
	copy(proofBytes[PointSize*33:PointSize*33+EightBytes], B_A_DeltaBytes)
	copy(proofBytes[PointSize*33+EightBytes:PointSize*33+EightBytes*2], B_B_DeltaBytes)
	copy(proofBytes[PointSize*33+EightBytes*2:PointSize*33+EightBytes*3], B_fee_DeltaBytes)
	copy(proofBytes[PointSize*33+EightBytes*3:PointSize*33+EightBytes*4], B_DaoABytes)
	copy(proofBytes[PointSize*33+EightBytes*4:PointSize*33+EightBytes*5], B_DaoBBytes)
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	AlphaBytes := make([]byte, EightBytes)
	BetaBytes := make([]byte, EightBytes)
	binary.BigEndian.PutUint64(AlphaBytes, proof.Alpha)
	binary.BigEndian.PutUint64(BetaBytes, proof.Beta)
	copy(proofBytes[PointSize*33+EightBytes*5:PointSize*33+EightBytes*6], AlphaBytes)
	copy(proofBytes[PointSize*33+EightBytes*6:PointSize*33+EightBytes*7], BetaBytes)
	// gamma = 1 - fee %
	GammaBytes := make([]byte, FourBytes)
	binary.BigEndian.PutUint32(GammaBytes, proof.Gamma)
	copy(proofBytes[PointSize*33+EightBytes*7:PointSize*33+EightBytes*7+FourBytes], GammaBytes)
	// range proofs
	copy(proofBytes[PointSize*33+EightBytes*7+FourBytes:PointSize*33+EightBytes*7+FourBytes+RangeProofSize], proof.ARangeProof.Bytes())
	copy(proofBytes[PointSize*33+EightBytes*7+FourBytes+RangeProofSize:PointSize*33+EightBytes*7+FourBytes+RangeProofSize*2], proof.FeeRangeProof.Bytes())
	return proofBytes
}

/*
	SwapProof: swap proof
*/
type SwapProof struct {
	// commitments
	// valid Enc
	A_C_ufeeL_Delta, A_CufeeR_DeltaHExpb_fee_DeltaInv *Point
	Z_r_Deltafee                                      *big.Int
	// Ownership
	A_pk_u, A_T_uAC_uARPrimeInv, A_T_ufeeC_ufeeRPrimeInv *Point
	Z_sk_u, Z_bar_r_A, Z_bar_r_fee, Z_sk_uInv            *big.Int
	// range proofs
	ARangeProof   *RangeProof
	FeeRangeProof *RangeProof
	// common inputs
	// user asset A balance enc
	C_uA *ElGamalEnc
	// user asset fee balance enc
	C_ufee *ElGamalEnc
	// user asset fee Delta enc
	C_ufee_Delta *ElGamalEnc
	// user asset A,B Delta enc
	C_uA_Delta, C_uB_Delta *ElGamalEnc
	// liquidity pool asset A,B Delta enc
	LC_DaoA_Delta, LC_DaoB_Delta *ElGamalEnc
	// public keys
	Pk_Dao, Pk_u *Point
	// random value for Delta A & B
	R_DeltaA, R_DeltaB *big.Int
	// commitment for user asset A & fee
	T_uA, T_ufee *Point
	// liquidity pool asset B balance
	LC_DaoB *ElGamalEnc
	// random value for dao liquidity asset B
	R_DaoB *big.Int
	// asset A,B,fee Delta & dao liquidity asset B balance
	B_A_Delta, B_B_Delta, B_fee_Delta uint64
	B_DaoA, B_DaoB                    uint64
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 1 - fee %
	Alpha, Beta uint64
	Gamma       uint32
	// generators
	AssetAId, AssetBId, AssetFeeId uint32
}

func (proof *SwapProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseSwapProofBytes(proofBytes []byte) (proof *SwapProof, err error) {
	if len(proofBytes) != SwapProofSize {
		return nil, errors.New("[ParseSwapProofBytes] invalid swap proof size")
	}
	// construct new proof
	proof = new(SwapProof)
	// valid Enc
	proof.A_C_ufeeL_Delta, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.A_CufeeR_DeltaHExpb_fee_DeltaInv, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.Z_r_Deltafee = new(big.Int).SetBytes(proofBytes[PointSize*2 : PointSize*3])
	// Ownership
	proof.A_pk_u, err = curve.FromBytes(proofBytes[PointSize*3 : PointSize*4])
	if err != nil {
		return nil, err
	}
	proof.A_T_uAC_uARPrimeInv, err = curve.FromBytes(proofBytes[PointSize*4 : PointSize*5])
	if err != nil {
		return nil, err
	}
	proof.A_T_ufeeC_ufeeRPrimeInv, err = curve.FromBytes(proofBytes[PointSize*5 : PointSize*6])
	if err != nil {
		return nil, err
	}
	proof.Z_sk_u = new(big.Int).SetBytes(proofBytes[PointSize*6 : PointSize*7])
	proof.Z_bar_r_A = new(big.Int).SetBytes(proofBytes[PointSize*7 : PointSize*8])
	proof.Z_bar_r_fee = new(big.Int).SetBytes(proofBytes[PointSize*8 : PointSize*9])
	proof.Z_sk_uInv = new(big.Int).SetBytes(proofBytes[PointSize*9 : PointSize*10])
	// common inputs
	// user asset A balance enc
	proof.C_uA, err = twistedElgamal.FromBytes(proofBytes[PointSize*10 : PointSize*12])
	if err != nil {
		return nil, err
	}
	// user asset fee balance enc
	proof.C_ufee, err = twistedElgamal.FromBytes(proofBytes[PointSize*12 : PointSize*14])
	if err != nil {
		return nil, err
	}
	// user asset fee Delta enc
	proof.C_ufee_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*14 : PointSize*16])
	if err != nil {
		return nil, err
	}
	// user asset A,B Delta enc
	proof.C_uA_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*16 : PointSize*18])
	if err != nil {
		return nil, err
	}
	proof.C_uB_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*18 : PointSize*20])
	if err != nil {
		return nil, err
	}
	// liquidity pool asset A,B Delta enc
	proof.LC_DaoA_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*20 : PointSize*22])
	if err != nil {
		return nil, err
	}
	proof.LC_DaoB_Delta, err = twistedElgamal.FromBytes(proofBytes[PointSize*22 : PointSize*24])
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
	proof.T_ufee, err = curve.FromBytes(proofBytes[PointSize*29 : PointSize*30])
	if err != nil {
		return nil, err
	}
	// liquidity pool asset B balance
	proof.LC_DaoB, err = twistedElgamal.FromBytes(proofBytes[PointSize*30 : PointSize*32])
	if err != nil {
		return nil, err
	}
	// random value for dao liquidity asset B
	proof.R_DaoB = new(big.Int).SetBytes(proofBytes[PointSize*32 : PointSize*33])
	// asset A,B,fee Delta & dao liquidity asset B balance
	proof.B_A_Delta = binary.BigEndian.Uint64(proofBytes[PointSize*33 : PointSize*33+EightBytes])
	proof.B_B_Delta = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes : PointSize*33+EightBytes*2])
	proof.B_fee_Delta = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*2 : PointSize*33+EightBytes*3])
	proof.B_DaoA = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*3 : PointSize*33+EightBytes*4])
	proof.B_DaoB = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*4 : PointSize*33+EightBytes*5])
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	proof.Alpha = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*5 : PointSize*33+EightBytes*6])
	proof.Beta = binary.BigEndian.Uint64(proofBytes[PointSize*33+EightBytes*6 : PointSize*33+EightBytes*7])
	// gamma = 1 - fee %
	proof.Gamma = binary.BigEndian.Uint32(proofBytes[PointSize*33+EightBytes*7 : PointSize*33+EightBytes*7+FourBytes])
	// range proofs
	proof.ARangeProof, err = ctrange.FromBytes(proofBytes[PointSize*33+EightBytes*7+FourBytes : PointSize*33+EightBytes*7+FourBytes+RangeProofSize])
	if err != nil {
		return nil, err
	}
	proof.FeeRangeProof, err = ctrange.FromBytes(proofBytes[PointSize*33+EightBytes*7+FourBytes+RangeProofSize : PointSize*33+EightBytes*7+FourBytes+RangeProofSize*2])
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func ParseSwapProofStr(proofStr string) (*SwapProof, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseSwapProofBytes(proofBytes)
}

/*
	SwapProofRelation: used to generate swap proof
*/
type SwapProofRelation struct {
	// public inputs
	// user asset A balance enc
	C_uA *ElGamalEnc
	// user asset fee balance enc
	C_ufee *ElGamalEnc
	// user asset fee Delta enc
	C_ufee_Delta *ElGamalEnc
	// user asset A,B Delta enc
	C_uA_Delta, C_uB_Delta *ElGamalEnc
	// liquidity pool asset A,B Delta enc
	LC_DaoA_Delta, LC_DaoB_Delta *ElGamalEnc
	// public keys
	Pk_Dao, Pk_u *Point
	// random value for Delta A & B
	R_DeltaA, R_DeltaB *big.Int
	// commitment for user asset A & fee
	T_uA, T_ufee *Point
	// liquidity pool asset B balance
	LC_DaoB *ElGamalEnc
	// random value for dao liquidity asset B
	R_DaoB *big.Int
	// asset A,B,fee Delta & dao liquidity asset B balance
	B_A_Delta, B_B_Delta, B_fee_Delta uint64
	B_DaoA, B_DaoB                    uint64
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 1 - fee %
	Alpha, Beta uint64
	Gamma       uint32
	// private inputs
	// user's private key
	Sk_u *big.Int
	// random value for delta fee
	R_Deltafee *big.Int
	// random value for commitment, will be used for range proof
	Bar_r_A, Bar_r_fee *big.Int
	// user asset A & fee new balance
	B_uA_prime, B_ufee_prime uint64
	// asset a id
	AssetAId uint32
	// asset b id
	AssetBId uint32
	// asset fee id
	AssetFeeId uint32
	// range proofs
	ARangeProof, FeeRangeProof *RangeProof
}

func NewSwapRelation(
	C_uA, C_ufee *ElGamalEnc,
	Pk_Dao, Pk_u *Point,
	assetAId, assetBId, assetFeeId uint32,
	B_A_Delta, B_B_Delta, B_fee_Delta, B_u_A, B_u_fee uint64,
	feeRate uint32,
	Sk_u *big.Int,
) (relation *SwapProofRelation, err error) {
	// check params
	if !notNullElGamal(C_uA) || !notNullElGamal(C_ufee) || Sk_u == nil ||
		Pk_Dao == nil || !curve.IsInSubGroup(Pk_Dao) || Pk_u == nil || !curve.IsInSubGroup(Pk_u) ||
		assetAId == assetBId ||
		B_u_A < B_A_Delta || B_u_fee < B_fee_Delta {
		log.Println("[NewSwapRelation] err: invalid params")
		if assetAId == assetFeeId && (!equalEnc(C_uA, C_ufee) || B_A_Delta+B_fee_Delta > B_u_A) {
			log.Println("[NewSwapRelation] not enough balance")
			return nil, errors.New("[NewSwapRelation] not enough balance")
		}
		return nil, errors.New("[NewSwapRelation] err: invalid params")
	}
	// check original balance
	hb_A, err := twistedElgamal.RawDec(C_uA, Sk_u)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	hb_ACheck := curve.ScalarMul(H, big.NewInt(int64(B_u_A)))
	if !hb_A.Equal(hb_ACheck) {
		log.Println("[NewSwapRelation] invalid hb_A")
		return nil, errors.New("[NewSwapRelation] invalid hb_A")
	}
	hb_fee, err := twistedElgamal.RawDec(C_ufee, Sk_u)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	hb_feeCheck := curve.ScalarMul(H, big.NewInt(int64(B_u_fee)))
	if !hb_fee.Equal(hb_feeCheck) {
		log.Println("[NewSwapRelation] invalid hb_fee")
		return nil, errors.New("[NewSwapRelation] invalid hb_fee")
	}
	// define variables
	var (
		C_ufee_Delta, C_uA_Delta, C_uB_Delta *ElGamalEnc
		LC_DaoA_Delta, LC_DaoB_Delta         *ElGamalEnc
		R_DeltaA, R_DeltaB                   *big.Int
		Gamma                                uint32
		Bar_r_A                              = new(big.Int)
		Bar_r_fee                            = new(big.Int)
		R_Deltafee                           *big.Int
		B_uA_prime, B_ufee_prime             uint64
		ARangeProof                          = new(RangeProof)
		FeeRangeProof                        = new(RangeProof)
		swapRangeChan                        = make(chan int, swapRangeProofCount)
	)
	// generate random values
	R_Deltafee = curve.RandomValue()
	R_DeltaA = curve.RandomValue()
	R_DeltaB = curve.RandomValue()
	// compute C_ufee_Delta
	C_ufee_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_fee_Delta)), R_Deltafee, Pk_u)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	// compute C_uA_Delta,C_uB_Delta
	C_uA_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_A_Delta)), R_DeltaA, Pk_u)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	C_uB_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_B_Delta)), R_DeltaB, Pk_u)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	// compute LC_DaoA_Delta,LC_DaoB_Delta
	LC_DaoA_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_A_Delta)), R_DeltaA, Pk_Dao)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	LC_DaoB_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_B_Delta)), R_DeltaB, Pk_Dao)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	// compute T_uA & T_ufee
	if assetFeeId == assetAId {
		B_uA_prime = B_u_A - B_A_Delta - B_fee_Delta
		B_ufee_prime = B_uA_prime
	} else {
		B_uA_prime = B_u_A - B_A_Delta
		B_ufee_prime = B_u_fee - B_fee_Delta
	}
	go proveCtRangeRoutine(int64(B_uA_prime), G, H, Bar_r_A, ARangeProof, swapRangeChan)
	go proveCtRangeRoutine(int64(B_ufee_prime), G, H, Bar_r_fee, FeeRangeProof, swapRangeChan)
	// compute Alpha, Beta, Gamma
	Gamma = OneThousand - feeRate
	for i := 0; i < swapRangeProofCount; i++ {
		val := <-swapRangeChan
		if val == ErrCode {
			return nil, errors.New("[NewSwapRelation] range proof works error")
		}
	}
	// construct swap proof relation
	relation = &SwapProofRelation{
		// public inputs
		// user asset A balance enc
		C_uA: C_uA,
		// user asset fee balance enc
		C_ufee: C_ufee,
		// user asset fee Delta enc
		C_ufee_Delta: C_ufee_Delta,
		// user asset A,B Delta enc
		C_uA_Delta: C_uA_Delta,
		C_uB_Delta: C_uB_Delta,
		// liquidity pool asset A,B Delta enc
		LC_DaoA_Delta: LC_DaoA_Delta,
		LC_DaoB_Delta: LC_DaoB_Delta,
		// public keys
		Pk_Dao: Pk_Dao,
		Pk_u:   Pk_u,
		// random value for Delta A & B
		R_DeltaA: R_DeltaA,
		R_DeltaB: R_DeltaB,
		// commitment for user asset A & fee
		T_uA:   new(Point).Set(ARangeProof.A),
		T_ufee: new(Point).Set(FeeRangeProof.A),
		// liquidity pool asset B balance, this will be added when operator received
		LC_DaoB: &ElGamalEnc{CL: curve.ZeroPoint(), CR: curve.ZeroPoint()},
		// R_Dao_B will be computed until operator received
		R_DaoB: big.NewInt(0),
		// asset A,B,fee Delta & dao liquidity asset B balance
		B_A_Delta:   B_A_Delta,
		B_B_Delta:   B_B_Delta,
		B_fee_Delta: B_fee_Delta,
		// alpha = \delta{x} / x
		// beta = \delta{y} / y
		// gamma = 1 - fee %
		Alpha: 0,
		Beta:  0,
		Gamma: Gamma,
		// private inputs
		// user's private key
		Sk_u: Sk_u,
		// random value for delta fee
		R_Deltafee: R_Deltafee,
		// random value for commitment, will be used for range proof
		Bar_r_A:   Bar_r_A,
		Bar_r_fee: Bar_r_fee,
		// user asset A & fee new balance
		B_uA_prime:   B_uA_prime,
		B_ufee_prime: B_ufee_prime,
		// asset a id
		AssetAId: assetAId,
		// asset b id
		AssetBId: assetBId,
		// asset fee id
		AssetFeeId: assetFeeId,
		// range proofs
		ARangeProof:   ARangeProof,
		FeeRangeProof: FeeRangeProof,
	}
	return relation, nil
}
