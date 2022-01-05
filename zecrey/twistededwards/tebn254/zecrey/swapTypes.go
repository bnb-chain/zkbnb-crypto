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
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
)

func (proof *SwapProof) Bytes() []byte {
	proofBytes := make([]byte, SwapProofSize)
	offset := 0
	// Ownership
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_pk_u.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_T_uAC_uARPrimeInv.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sk_u.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bar_r_A.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_sk_uInv.FillBytes(make([]byte, PointSize)))
	// common inputs
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uA))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_treasuryfee_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uA_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_uB_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.LC_poolA_Delta))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.LC_poolB_Delta))

	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk_pool.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk_u.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Pk_treasury.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_DeltaA.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_DeltaB.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.R_Deltafee.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.T_uA.Marshal())

	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_A_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_B_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_treasuryfee_Delta))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_poolA))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.B_poolB))
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.Alpha))
	// gas fee
	// gamma = 1 - fee %
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.Gamma))
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.AssetAId))
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.AssetBId))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.MinB_B_Delta))
	// range proofs
	offset = copyBuf(&proofBytes, offset, RangeProofSize, proof.ARangeProof.Bytes())
	// gas fee
	offset = copyBuf(&proofBytes, offset, PointSize, proof.A_T_feeC_feeRPrimeInv.Marshal())
	offset = copyBuf(&proofBytes, offset, PointSize, proof.Z_bar_r_fee.FillBytes(make([]byte, PointSize)))
	offset = copyBuf(&proofBytes, offset, ElGamalEncSize, elgamalToBytes(proof.C_fee))
	offset = copyBuf(&proofBytes, offset, PointSize, proof.T_fee.Marshal())
	offset = copyBuf(&proofBytes, offset, FourBytes, uint32ToBytes(proof.GasFeeAssetId))
	offset = copyBuf(&proofBytes, offset, EightBytes, uint64ToBytes(proof.GasFee))
	offset = copyBuf(&proofBytes, offset, RangeProofSize, proof.GasFeePrimeRangeProof.Bytes())
	return proofBytes
}

/*
	SwapProof: swap proof
*/
type SwapProof struct {
	// commitments
	// Ownership
	A_pk_u, A_T_uAC_uARPrimeInv  *Point
	Z_sk_u, Z_bar_r_A, Z_sk_uInv *big.Int
	// range proofs
	ARangeProof *RangeProof
	// common inputs
	// user asset A balance enc
	C_uA *ElGamalEnc
	// treasury asset fee Delta enc
	C_treasuryfee_Delta *ElGamalEnc
	// user asset A,B Delta enc
	C_uA_Delta, C_uB_Delta *ElGamalEnc
	// liquidity pool asset A,B Delta enc
	LC_poolA_Delta, LC_poolB_Delta *ElGamalEnc
	// public keys
	Pk_pool, Pk_u, Pk_treasury *Point
	// random value for Delta A & B
	R_DeltaA, R_DeltaB, R_Deltafee *big.Int
	// commitment for user asset A & fee
	T_uA *Point
	// asset A,B,fee Delta & pool liquidity asset B balance
	B_A_Delta, B_B_Delta, B_treasuryfee_Delta uint64
	B_poolA, B_poolB                          uint64
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	Alpha uint64
	// gamma = 10000 - fee
	Gamma uint32
	// asset a id
	AssetAId uint32
	// asset b id
	AssetBId     uint32
	MinB_B_Delta uint64
	// gas fee
	A_T_feeC_feeRPrimeInv *Point
	Z_bar_r_fee           *big.Int
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	GasFeeAssetId         uint32
	GasFee                uint64
	GasFeePrimeRangeProof *RangeProof
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
	offset := 0
	// Ownership
	offset, proof.A_pk_u, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.A_T_uAC_uARPrimeInv, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Z_sk_u = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_bar_r_A = readBigIntFromBuf(proofBytes, offset)
	offset, proof.Z_sk_uInv = readBigIntFromBuf(proofBytes, offset)
	// common inputs
	// user asset A balance enc
	offset, proof.C_uA, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// treasury asset fee balance enc
	offset, proof.C_treasuryfee_Delta, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// user asset A,B Delta enc
	offset, proof.C_uA_Delta, err = readElGamalEncFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
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
	// public keys
	offset, proof.Pk_pool, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Pk_u, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	offset, proof.Pk_treasury, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// random value for Delta A & B
	offset, proof.R_DeltaA = readBigIntFromBuf(proofBytes, offset)
	offset, proof.R_DeltaB = readBigIntFromBuf(proofBytes, offset)
	offset, proof.R_Deltafee = readBigIntFromBuf(proofBytes, offset)
	// commitment for user asset A & fee
	offset, proof.T_uA, err = readPointFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// asset A,B,fee Delta & dao liquidity asset B balance
	offset, proof.B_A_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_B_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_treasuryfee_Delta = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_poolA = readUint64FromBuf(proofBytes, offset)
	offset, proof.B_poolB = readUint64FromBuf(proofBytes, offset)
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	offset, proof.Alpha = readUint64FromBuf(proofBytes, offset)
	// gamma = 1 - fee %
	offset, proof.Gamma = readUint32FromBuf(proofBytes, offset)
	offset, proof.AssetAId = readUint32FromBuf(proofBytes, offset)
	offset, proof.AssetBId = readUint32FromBuf(proofBytes, offset)
	offset, proof.MinB_B_Delta = readUint64FromBuf(proofBytes, offset)
	// range proofs
	offset, proof.ARangeProof, err = readRangeProofFromBuf(proofBytes, offset)
	if err != nil {
		return nil, err
	}
	// gas fee
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
	// treasury asset fee Delta enc
	C_treasuryfee_Delta *ElGamalEnc
	// user asset A,B Delta enc
	C_uA_Delta, C_uB_Delta *ElGamalEnc
	// liquidity pool asset A,B Delta enc
	LC_poolA_Delta, LC_poolB_Delta *ElGamalEnc
	// public keys
	Pk_pool, Pk_u, Pk_treasury *Point
	// random value for Delta A & B & fee
	R_DeltaA, R_DeltaB, R_Deltafee *big.Int
	// commitment for user asset A & fee
	T_uA *Point
	// asset A,B,fee Delta & dao liquidity asset B balance
	B_A_Delta, B_B_Delta, B_treasuryfee_Delta uint64
	B_poolA, B_poolB                          uint64
	// alpha = \delta{x} / x
	// beta = \delta{y} / y
	// gamma = 1 - fee %
	Alpha uint64
	Gamma uint32
	// asset a id
	AssetAId uint32
	// asset b id
	AssetBId uint32
	// private inputs
	// user's private key
	Sk_u *big.Int
	// random value for commitment, will be used for range proof
	Bar_r_A *big.Int
	// user asset A & fee new balance
	B_uA_prime uint64
	// range proofs
	ARangeProof *RangeProof
	// min
	MinB_B_Delta uint64
	// gas fee
	B_fee_prime           uint64
	C_fee                 *ElGamalEnc
	T_fee                 *Point
	Bar_r_fee             *big.Int
	GasFeeAssetId         uint32
	GasFee                uint64
	GasFeePrimeRangeProof *RangeProof
}

func NewSwapRelation(
	C_uA *ElGamalEnc,
	Pk_u, Pk_treasury *Point,
	assetAId, assetBId uint32,
	B_A_Delta, B_u_A uint64,
	MinB_B_Delta uint64,
	feeRate uint32, treasuryRate uint32,
	Sk_u *big.Int,
	// fee part
	C_fee *ElGamalEnc, B_fee uint64, GasFeeAssetId uint32, GasFee uint64,
) (relation *SwapProofRelation, err error) {
	// check params
	if !notNullElGamal(C_uA) || Sk_u == nil ||
		Pk_treasury == nil || !curve.IsInSubGroup(Pk_treasury) ||
		Pk_u == nil || !curve.IsInSubGroup(Pk_u) || treasuryRate > feeRate || treasuryRate > MaxFeeRate || feeRate > MaxFeeRate ||
		assetAId == assetBId || B_fee < GasFee || (assetAId == GasFeeAssetId && (!equalEnc(C_uA, C_fee) || B_u_A != B_fee || B_u_A < B_A_Delta+GasFee)) {
		log.Println("[NewSwapRelation] err: invalid params")
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
	// define variables
	var (
		C_uA_Delta          *ElGamalEnc
		C_treasuryfee_Delta *ElGamalEnc
		B_treasuryfee_Delta uint64
		R_DeltaA            *big.Int
		Gamma               uint32
		Bar_r_A             = new(big.Int)
		R_Deltafee          *big.Int
		B_uA_prime          uint64
		ARangeProof         = new(RangeProof)
		// gas fee
		B_fee_prime           uint64
		Bar_r_fee             = new(big.Int)
		GasFeePrimeRangeProof = new(RangeProof)
	)
	// compute B_poolA_Delta
	B_treasuryfee_Delta = uint64(
		math.Floor(
			float64(
				ffmath.Div(
					ffmath.Multiply(
						big.NewInt(int64(B_A_Delta)), big.NewInt(int64(treasuryRate)),
					),
					big.NewInt(int64(TenThousand))).Uint64(),
			),
		),
	)
	if B_treasuryfee_Delta == 0 {
		B_treasuryfee_Delta = MinFee
	}
	// generate random values
	R_Deltafee = curve.RandomValue()
	R_DeltaA = curve.RandomValue()
	// compute C_uA_Delta,C_uB_Delta
	C_uA_Delta, err = twistedElgamal.EncNeg(big.NewInt(int64(B_A_Delta)), R_DeltaA, Pk_u)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	// compute C_treasuryfee_Delta
	C_treasuryfee_Delta, err = twistedElgamal.Enc(big.NewInt(int64(B_treasuryfee_Delta)), R_Deltafee, Pk_treasury)
	if err != nil {
		log.Println("[NewSwapRelation] err info:", err)
		return nil, err
	}
	if GasFeeAssetId == assetAId {
		// compute B_uA_prime
		B_uA_prime = B_u_A - B_A_Delta - GasFee
		var (
			swapRangeCount = 1
			swapRangeChan  = make(chan int, swapRangeCount)
		)
		// prove b_u_A' is greater than 0
		go proveCtRangeRoutine(int64(B_uA_prime), G, H, Bar_r_A, ARangeProof, swapRangeChan)
		for i := 0; i < swapRangeCount; i++ {
			val := <-swapRangeChan
			if val == ErrCode {
				return nil, errors.New("[NewSwapRelation] range proof works error")
			}
		}
		// gas part
		B_fee_prime = B_uA_prime
		Bar_r_fee.Set(Bar_r_A)
		GasFeePrimeRangeProof = ARangeProof
	} else {
		// compute B_uA_prime
		B_uA_prime = B_u_A - B_A_Delta
		B_fee_prime = B_fee - GasFee
		var (
			swapRangeCount = 2
			swapRangeChan  = make(chan int, swapRangeCount)
		)
		// prove b_u_A' is greater than 0
		go proveCtRangeRoutine(int64(B_uA_prime), G, H, Bar_r_A, ARangeProof, swapRangeChan)
		// gas part
		go proveCtRangeRoutine(int64(B_fee_prime), G, H, Bar_r_fee, GasFeePrimeRangeProof, swapRangeChan)
		for i := 0; i < swapRangeCount; i++ {
			val := <-swapRangeChan
			if val == ErrCode {
				return nil, errors.New("[NewSwapRelation] range proof works error")
			}
		}
	}
	// compute Alpha, Beta, Gamma
	Gamma = TenThousand - feeRate
	// construct swap proof relation
	relation = &SwapProofRelation{
		C_uA:                C_uA,
		C_treasuryfee_Delta: C_treasuryfee_Delta,
		C_uA_Delta:          C_uA_Delta,
		C_uB_Delta:          zeroElGamal(),
		LC_poolA_Delta:      zeroElGamal(),
		LC_poolB_Delta:      zeroElGamal(),
		Pk_pool:             curve.ZeroPoint(),
		Pk_u:                Pk_u,
		Pk_treasury:         Pk_treasury,
		R_DeltaA:            R_DeltaA,
		R_DeltaB:            curve.RandomValue(),
		R_Deltafee:          R_Deltafee,
		T_uA:                new(Point).Set(ARangeProof.A),
		B_A_Delta:           B_A_Delta,
		B_B_Delta:           0,
		B_treasuryfee_Delta: B_treasuryfee_Delta,
		//B_poolA:               0,
		//B_poolB:               0,
		//Alpha:                 0,
		Gamma:                 Gamma,
		AssetAId:              assetAId,
		AssetBId:              assetBId,
		Sk_u:                  Sk_u,
		Bar_r_A:               Bar_r_A,
		B_uA_prime:            B_uA_prime,
		ARangeProof:           ARangeProof,
		MinB_B_Delta:          MinB_B_Delta,
		B_fee_prime:           B_fee_prime,
		Bar_r_fee:             Bar_r_fee,
		C_fee:                 C_fee,
		T_fee:                 new(Point).Set(GasFeePrimeRangeProof.A),
		GasFeeAssetId:         GasFeeAssetId,
		GasFee:                GasFee,
		GasFeePrimeRangeProof: GasFeePrimeRangeProof,
	}
	return relation, nil
}
