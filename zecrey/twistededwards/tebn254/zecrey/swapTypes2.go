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
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

/*
	SwapProof2: swap proof
*/
type SwapProof2 struct {
	// commitments
	// valid Enc
	A_C_ufeeL_Delta, A_CufeeR_DeltaHb_fee_DeltaInv *Point
	Z_r_Deltafee                                   *big.Int
	// Ownership
	A_Pk_u, A_T_uAC_uARPrimeInv, A_T_ufeeC_ufeeRPrimeInv *Point
	Z_sk_u, Z_bar_r_A, Z_bar_r_fee, Z_sk_uInv            *big.Int
	// range proofs
	ARangeProof   *commitRange.ComRangeProof
	FeeRangeProof *commitRange.ComRangeProof
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
	B_A_Delta, B_B_Delta, B_fee_Delta, B_DaoB uint32
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 1 - fee %
	Alpha, Beta *big.Int
	Gamma       uint32
	// generators
	G, H *Point
}

func (proof *SwapProof2) Bytes() []byte {
	proofBytes := make([]byte, SwapProofSize2)
	// valid Enc
	copy(proofBytes[:PointSize], proof.A_C_ufeeL_Delta.Marshal())
	copy(proofBytes[PointSize:PointSize*2], proof.A_CufeeR_DeltaHb_fee_DeltaInv.Marshal())
	copy(proofBytes[PointSize*2:PointSize*3], proof.Z_r_Deltafee.FillBytes(make([]byte, PointSize)))
	// Ownership
	copy(proofBytes[PointSize*3:PointSize*4], proof.A_Pk_u.Marshal())
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
	// generators
	copy(proofBytes[PointSize*33:PointSize*34], proof.G.Marshal())
	copy(proofBytes[PointSize*34:PointSize*35], proof.H.Marshal())
	// asset A,B,fee Delta & dao liquidity asset B balance
	B_A_DeltaBytes := make([]byte, FourBytes)
	B_B_DeltaBytes := make([]byte, FourBytes)
	B_fee_DeltaBytes := make([]byte, FourBytes)
	B_DaoBBytes := make([]byte, FourBytes)
	binary.BigEndian.PutUint32(B_A_DeltaBytes, proof.B_A_Delta)
	binary.BigEndian.PutUint32(B_B_DeltaBytes, proof.B_B_Delta)
	binary.BigEndian.PutUint32(B_fee_DeltaBytes, proof.B_fee_Delta)
	binary.BigEndian.PutUint32(B_DaoBBytes, proof.B_DaoB)
	copy(proofBytes[PointSize*35:PointSize*35+FourBytes], B_A_DeltaBytes)
	copy(proofBytes[PointSize*35+FourBytes:PointSize*35+FourBytes*2], B_B_DeltaBytes)
	copy(proofBytes[PointSize*35+FourBytes*2:PointSize*35+FourBytes*3], B_fee_DeltaBytes)
	copy(proofBytes[PointSize*35+FourBytes*3:PointSize*35+FourBytes*4], B_DaoBBytes)
	// gamma
	GammaBytes := make([]byte, FourBytes)
	binary.BigEndian.PutUint32(GammaBytes, proof.Gamma)
	copy(proofBytes[PointSize*35+FourBytes*4:PointSize*35+FourBytes*5], GammaBytes)
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 1 - fee %
	copy(proofBytes[PointSize*35+FourBytes*5:PointSize*35+FourBytes*5+EightBytes], proof.Alpha.FillBytes(make([]byte, EightBytes)))
	copy(proofBytes[PointSize*35+FourBytes*5+EightBytes:PointSize*35+FourBytes*5+EightBytes*2], proof.Beta.FillBytes(make([]byte, EightBytes)))
	// range proofs
	copy(proofBytes[PointSize*35+FourBytes*5+EightBytes*2:PointSize*35+FourBytes*5+EightBytes*2+RangeProofSize], proof.ARangeProof.Bytes())
	copy(proofBytes[PointSize*35+FourBytes*5+EightBytes*2+RangeProofSize:PointSize*35+FourBytes*5+EightBytes*2+RangeProofSize*2], proof.FeeRangeProof.Bytes())
	return proofBytes
}

func (proof *SwapProof2) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func ParseSwapProof2Bytes(proofBytes []byte) (proof *SwapProof2, err error) {
	if len(proofBytes) != SwapProofSize2 {
		return nil, errors.New("[ParseSwapProof2Bytes] invalid swap proof size")
	}
	// construct new proof
	proof = new(SwapProof2)
	// valid Enc
	proof.A_C_ufeeL_Delta, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.A_CufeeR_DeltaHb_fee_DeltaInv, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.Z_r_Deltafee = new(big.Int).SetBytes(proofBytes[PointSize*2 : PointSize*3])
	// Ownership
	proof.A_Pk_u, err = curve.FromBytes(proofBytes[PointSize*3 : PointSize*4])
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
	// generators
	proof.G, err = curve.FromBytes(proofBytes[PointSize*33 : PointSize*34])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[PointSize*34 : PointSize*35])
	if err != nil {
		return nil, err
	}
	// asset A,B,fee Delta & dao liquidity asset B balance
	proof.B_A_Delta = binary.BigEndian.Uint32(proofBytes[PointSize*35 : PointSize*35+FourBytes])
	proof.B_B_Delta = binary.BigEndian.Uint32(proofBytes[PointSize*35+FourBytes : PointSize*35+FourBytes*2])
	proof.B_fee_Delta = binary.BigEndian.Uint32(proofBytes[PointSize*35+FourBytes*2 : PointSize*35+FourBytes*3])
	proof.B_DaoB = binary.BigEndian.Uint32(proofBytes[PointSize*35+FourBytes*3 : PointSize*35+FourBytes*4])
	// gamma
	proof.Gamma = binary.BigEndian.Uint32(proofBytes[PointSize*35+FourBytes*4 : PointSize*35+FourBytes*5])
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 1 - fee %
	proof.Alpha = new(big.Int).SetBytes(proofBytes[PointSize*35+FourBytes*5 : PointSize*35+FourBytes*5+EightBytes])
	proof.Beta = new(big.Int).SetBytes(proofBytes[PointSize*35+FourBytes*5+EightBytes : PointSize*35+FourBytes*5+EightBytes*2])
	// range proofs
	proof.ARangeProof, err = commitRange.FromBytes(proofBytes[PointSize*35+FourBytes*5+EightBytes*2 : PointSize*35+FourBytes*5+EightBytes*2+RangeProofSize])
	proof.FeeRangeProof, err = commitRange.FromBytes(proofBytes[PointSize*35+FourBytes*5+EightBytes*2+RangeProofSize : PointSize*35+FourBytes*5+EightBytes*2+RangeProofSize*2])
	return proof, nil
}

func ParseSwapProof2Str(proofStr string) (*SwapProof2, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return ParseSwapProof2Bytes(proofBytes)
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
	B_A_Delta, B_B_Delta, B_fee_Delta, B_DaoB uint32
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 1 - fee %
	Alpha, Beta *big.Int
	Gamma       uint32
	// generators
	G, H *Point
	// private inputs
	// user's private key
	Sk_u *big.Int
	// random value for delta fee
	R_Deltafee *big.Int
	// random value for commitment, will be used for range proof
	Bar_r_A, Bar_r_fee *big.Int
	// user asset A & fee new balance
	B_uA_prime, B_ufee_prime uint32
	// asset a id
	AssetAId uint32
	// asset b id
	AssetBId uint32
	// asset fee id
	AssetFeeId uint32
	// Ht_A = h^{asset_A_id}
	Ht_A *Point
	// Ht_B = h^{asset_B_id}
	Ht_B *Point
	// Ht_fee = h^{asset_fee_id}
	Ht_fee *Point
	// Pt_A = Ht_A^{sk_a}
	Pt_A *Point
	// Pt_B = Ht_B^{sk_a}
	Pt_B *Point
	// Pt_fee = Ht_fee^{sk_a}
	Pt_fee *Point
}

func NewSwapRelation(
	C_uA, C_ufee *ElGamalEnc,
	Pk_Dao, Pk_u *Point,
	assetAId, assetBId, assetFeeId uint32,
	b_A_Delta, b_B_Delta, b_fee_Delta, b_u_A, b_u_fee uint32,
	b_Dao_A, b_Dao_B uint32,
	feeRate uint32,
	sk_u *big.Int,
) (relation *SwapProofRelation, err error) {
	// check params
	if !notNullElGamal(C_uA) || !notNullElGamal(C_ufee) ||
		Pk_Dao == nil || !curve.IsInSubGroup(Pk_Dao) || Pk_u == nil || !curve.IsInSubGroup(Pk_u) ||
		assetAId == assetBId || b_B_Delta > b_Dao_B || b_A_Delta > b_u_A || b_fee_Delta > b_u_fee {
		return nil, errors.New("[NewSwapRelation] err: invalid params")
	}
	// define variables
	var (
		C_ufee_Delta, C_uA_Delta, C_uB_Delta *ElGamalEnc
		LC_DaoA_Delta, LC_DaoB_Delta         *ElGamalEnc
		R_DeltaA, R_DeltaB                   *big.Int
		T_uA, T_ufee                         *Point
		Alpha, Beta                          *big.Int
		Gamma                                uint32
		Bar_r_A, Bar_r_fee                   *big.Int
		Ht_A, Ht_B, Ht_fee                   *Point
		Pt_A, Pt_B, Pt_fee                   *Point
		R_Deltafee                           *big.Int
	)
	// check if C is correct
	hExpb_uA, err := twistedElgamal.RawDec(C_uA, sk_u)
	if err != nil {
		return nil, err
	}
	check_hExpb_uA := curve.ScalarMul(curve.H, big.NewInt(int64(b_u_A)))
	if !check_hExpb_uA.Equal(hExpb_uA) {
		return nil, errors.New("[NewSwapRelation] err: invalid balance for b_u_A")
	}
	hExpb_ufee, err := twistedElgamal.RawDec(C_ufee, sk_u)
	if err != nil {
		return nil, err
	}
	check_hExpb_ufee := curve.ScalarMul(curve.H, big.NewInt(int64(b_u_fee)))
	if !check_hExpb_ufee.Equal(hExpb_ufee) {
		return nil, errors.New("[NewSwapRelation] err: invalid balance for b_u_fee")
	}
	// generate random values
	R_Deltafee = curve.RandomValue()
	R_DeltaA = curve.RandomValue()
	R_DeltaB = curve.RandomValue()
	Bar_r_A = curve.RandomValue()
	Bar_r_fee = curve.RandomValue()
	// compute C_ufee_Delta
	C_ufee_Delta, err = twistedElgamal.Enc(big.NewInt(int64(b_fee_Delta)), R_Deltafee, Pk_u)
	if err != nil {
		return nil, err
	}
	// compute C_uA_Delta,C_uB_Delta
	C_uA_Delta, err = twistedElgamal.Enc(big.NewInt(int64(b_A_Delta)), R_DeltaA, Pk_u)
	if err != nil {
		return nil, err
	}
	C_uB_Delta, err = twistedElgamal.Enc(big.NewInt(int64(b_B_Delta)), R_DeltaB, Pk_u)
	if err != nil {
		return nil, err
	}
	// compute LC_DaoA_Delta,LC_DaoB_Delta
	LC_DaoA_Delta, err = twistedElgamal.Enc(big.NewInt(int64(b_A_Delta)), R_DeltaA, Pk_Dao)
	if err != nil {
		return nil, err
	}
	LC_DaoB_Delta, err = twistedElgamal.Enc(big.NewInt(int64(b_B_Delta)), R_DeltaB, Pk_Dao)
	if err != nil {
		return nil, err
	}
	// compute T_uA & T_ufee
	T_uA = curve.Add(curve.ScalarMul(curve.G, Bar_r_A), curve.ScalarMul(curve.H, big.NewInt(int64(b_u_A))))
	T_ufee = curve.Add(curve.ScalarMul(curve.G, Bar_r_fee), curve.ScalarMul(curve.H, big.NewInt(int64(b_u_fee))))
	// compute Ht & Pt
	Ht_A = curve.ScalarMul(curve.H, big.NewInt(int64(assetAId)))
	Ht_B = curve.ScalarMul(curve.H, big.NewInt(int64(assetBId)))
	Ht_fee = curve.ScalarMul(curve.H, big.NewInt(int64(assetFeeId)))
	Pt_A = curve.ScalarMul(Ht_A, sk_u)
	Pt_B = curve.ScalarMul(Ht_B, sk_u)
	Pt_fee = curve.ScalarMul(Ht_fee, sk_u)
	// compute Alpha, Beta, Gamma
	Alpha = big.NewInt(int64(float64(b_A_Delta) / float64(b_Dao_A) * OneMillion))
	Beta = big.NewInt(int64(float64(b_B_Delta) / float64(b_Dao_B) * OneMillion))
	Gamma = 1000 - feeRate
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
		T_uA:   T_uA,
		T_ufee: T_ufee,
		// liquidity pool asset B balance, this will be added when operator received
		// LC_DaoB: LC_DaoB,
		// R_Dao_B will be computed until operator received
		//R_DaoB: R_DaoB,
		// asset A,B,fee Delta & dao liquidity asset B balance
		B_A_Delta:   b_A_Delta,
		B_B_Delta:   b_B_Delta,
		B_fee_Delta: b_fee_Delta,
		B_DaoB:      b_Dao_B,
		// alpha = \delta{x} / x
		// beta = \delta{y} / y
		// gamma = 1 - fee %
		Alpha: Alpha,
		Beta:  Beta,
		Gamma: Gamma,
		// generators
		G: curve.G,
		H: curve.H,
		// private inputs
		// user's private key
		Sk_u: sk_u,
		// random value for delta fee
		R_Deltafee: R_Deltafee,
		// random value for commitment, will be used for range proof
		Bar_r_A:   Bar_r_A,
		Bar_r_fee: Bar_r_fee,
		// user asset A & fee new balance
		B_uA_prime:   b_u_A - b_A_Delta,
		B_ufee_prime: b_u_fee - b_fee_Delta,
		// asset a id
		AssetAId: assetAId,
		// asset b id
		AssetBId: assetBId,
		// asset fee id
		AssetFeeId: assetFeeId,
		// Ht_A = h^{asset_A_id}
		Ht_A: Ht_A,
		// Ht_B = h^{asset_B_id}
		Ht_B: Ht_B,
		// Ht_fee = h^{asset_fee_id}
		Ht_fee: Ht_fee,
		// Pt_A = Ht_A^{sk_a}
		Pt_A: Pt_A,
		// Pt_B = Ht_B^{sk_a}
		Pt_B: Pt_B,
		// Pt_fee = Ht_fee^{sk_a}
		Pt_fee: Pt_fee,
	}
	return relation, nil
}
