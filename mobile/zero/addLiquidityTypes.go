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

package zero

import (
	"encoding/json"
	"errors"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"log"
	"math/big"
)

type AddLiquiditySegment struct {
	PairIndex            uint32
	AccountIndex         uint32
	C_uA, C_uB           *ElGamalEnc
	Pk_pool, Pk_u        *Point
	AssetAId, AssetBId   uint32
	B_uA, B_uB           uint64
	B_A_Delta, B_B_Delta uint64
	Sk_u                 *big.Int
	// fee part
	C_fee         *ElGamalEnc
	B_fee         uint64
	GasFeeAssetId uint32
	GasFee        uint64
}

type AddLiquiditySegmentFormat struct {
	PairIndex    int    `json:"pair_index"`
	AccountIndex int    `json:"account_index"`
	C_uA         string `json:"c_u_a"`
	C_uB         string `json:"c_u_b"`
	Pk_pool      string `json:"pk_pool"`
	Pk_u         string `json:"pk_u"`
	AssetAId     int    `json:"asset_a_id"`
	AssetBId     int    `json:"asset_b_id"`
	B_uA         int64  `json:"b_u_a"`
	B_uB         int64  `json:"b_u_b"`
	B_A_Delta    int64  `json:"b_a_delta"`
	B_B_Delta    int64  `json:"b_b_delta"`
	Sk_u         string `json:"sk_u"`
	// fee part
	C_fee         string `json:"c_fee"`
	B_fee         int64  `json:"b_fee"`
	GasFeeAssetId int    `json:"gas_fee_asset_id"`
	GasFee        int64  `json:"gas_fee"`
}

func FromAddLiquiditySegmentJSON(segmentStr string) (segment *AddLiquiditySegment, err error) {
	var segmentFormat *AddLiquiditySegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", err)
		return nil, err
	}
	if segmentFormat.C_uA == "" || segmentFormat.C_uB == "" || segmentFormat.C_fee == "" || segmentFormat.Pk_u == "" || segmentFormat.Pk_pool == "" ||
		segmentFormat.Sk_u == "" {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", ErrInvalidSwapParams)
		return nil, errors.New("[FromAddLiquiditySegmentJSON] invalid params")
	}
	// verify params
	if segmentFormat.PairIndex < 0 || segmentFormat.AccountIndex < 0 ||
		segmentFormat.AssetAId < 0 || segmentFormat.AssetBId < 0 || segmentFormat.AssetAId == segmentFormat.AssetBId ||
		segmentFormat.B_uA < 0 || segmentFormat.B_uB < 0 || segmentFormat.B_uA < segmentFormat.B_A_Delta || segmentFormat.B_uB < segmentFormat.B_B_Delta ||
		segmentFormat.B_A_Delta < 0 || segmentFormat.B_B_Delta < 0 || segmentFormat.B_fee < 0 || segmentFormat.GasFeeAssetId < 0 || segmentFormat.GasFee < 0 {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", ErrInvalidSwapParams)
		return nil, errors.New("[FromAddLiquiditySegmentJSON] invalid params")
	}
	C_uA, err := twistedElgamal.FromString(segmentFormat.C_uA)
	if err != nil {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", err)
		return nil, err
	}
	C_uB, err := twistedElgamal.FromString(segmentFormat.C_uB)
	if err != nil {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", err)
		return nil, err
	}
	Pk_pool, err := curve.FromString(segmentFormat.Pk_pool)
	if err != nil {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", err)
		return nil, err
	}
	Pk_u, err := curve.FromString(segmentFormat.Pk_u)
	if err != nil {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", err)
		return nil, err
	}
	Sk, isValid := new(big.Int).SetString(segmentFormat.Sk_u, 10)
	if !isValid {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", ErrParseBigInt)
		return nil, err
	}
	C_fee, err := twistedElgamal.FromString(segmentFormat.C_fee)
	if err != nil {
		log.Println("[FromAddLiquiditySegmentJSON] err info:", err)
		return nil, err
	}
	swapSegment := &AddLiquiditySegment{
		PairIndex:     uint32(segmentFormat.PairIndex),
		AccountIndex:  uint32(segmentFormat.AccountIndex),
		C_uA:          C_uA,
		C_uB:          C_uB,
		Pk_pool:       Pk_pool,
		Pk_u:          Pk_u,
		AssetAId:      uint32(segmentFormat.AssetAId),
		AssetBId:      uint32(segmentFormat.AssetBId),
		B_uA:          uint64(segmentFormat.B_uA),
		B_uB:          uint64(segmentFormat.B_uB),
		B_A_Delta:     uint64(segmentFormat.B_A_Delta),
		B_B_Delta:     uint64(segmentFormat.B_B_Delta),
		Sk_u:          Sk,
		C_fee:         C_fee,
		B_fee:         uint64(segmentFormat.B_fee),
		GasFeeAssetId: uint32(segmentFormat.GasFeeAssetId),
		GasFee:        uint64(segmentFormat.GasFee),
	}
	return swapSegment, nil
}

type AddLiquidityTxInfo struct {
	PairIndex    uint32
	AccountIndex uint32
	AssetAId     uint32
	AssetBId     uint32
	// swap amount
	B_A_Delta uint64
	B_B_Delta uint64
	// gas fee part
	GasFeeAssetId uint32
	GasFee        uint64
	Proof         string
}
