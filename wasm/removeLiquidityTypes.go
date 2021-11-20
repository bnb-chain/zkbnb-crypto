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

package wasm

import (
	"encoding/json"
	"log"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

type RemoveLiquiditySegment struct {
	PairIndex                  uint32
	AccountIndex               uint32
	C_u_LP                     *ElGamalEnc
	Pk_u                       *Point
	B_LP                       uint64
	Delta_LP                   uint64
	MinB_A_Delta, MinB_B_Delta uint64
	AssetAId, AssetBId         uint32
	Sk_u                       *big.Int
	// fee part
	C_fee         *ElGamalEnc
	B_fee         uint64
	GasFeeAssetId uint32
	GasFee        uint64
}

type RemoveLiquiditySegmentFormat struct {
	PairIndex    int    `json:"pair_index"`
	AccountIndex int    `json:"account_index"`
	C_u_LP       string `json:"c_u_lp"`
	Pk_u         string `json:"pk_u"`
	B_LP         int64  `json:"b_lp"`
	Delta_LP     int64  `json:"delta_lp"`
	MinB_A_Delta int64  `json:"min_b_a_delta"`
	MinB_B_Delta int64  `json:"min_b_b_delta"`
	AssetAId     int    `json:"asset_a_id"`
	AssetBId     int    `json:"asset_b_id"`
	Sk_u         string `json:"sk_u"`
	// fee part
	C_fee         string `json:"c_fee"`
	B_fee         int64  `json:"b_fee"`
	GasFeeAssetId int    `json:"gas_fee_asset_id"`
	GasFee        int64  `json:"gas_fee"`
}

func FromRemoveLiquiditySegmentJSON(segmentStr string) (*RemoveLiquiditySegment, string) {
	var segmentFormat *RemoveLiquiditySegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[FromRemoveLiquiditySegmentJSON] err info:", err)
		return nil, ErrUnmarshal
	}
	if segmentFormat.C_u_LP == "" || segmentFormat.C_fee == "" || segmentFormat.Pk_u == "" ||
		segmentFormat.Sk_u == "" {
		log.Println("[FromRemoveLiquiditySegmentJSON] err info:", ErrInvalidSwapParams)
		return nil, ErrInvalidSwapParams
	}
	// verify params
	if segmentFormat.PairIndex < 0 || segmentFormat.AccountIndex < 0 || segmentFormat.B_LP < 0 ||
		segmentFormat.Delta_LP < 0 || segmentFormat.MinB_A_Delta < 0 || segmentFormat.MinB_B_Delta < 0 ||
		segmentFormat.AssetAId < 0 || segmentFormat.AssetBId < 0 || segmentFormat.AssetAId == segmentFormat.AssetBId ||
		segmentFormat.B_fee < 0 || segmentFormat.GasFeeAssetId < 0 || segmentFormat.GasFee < 0 {
		log.Println("[FromRemoveLiquiditySegmentJSON] err info:", ErrInvalidSwapParams)
		return nil, ErrInvalidRemoveLiquidityParams
	}
	C_u_LP, err := twistedElgamal.FromString(segmentFormat.C_u_LP)
	if err != nil {
		log.Println("[FromRemoveLiquiditySegmentJSON] err info:", err)
		return nil, ErrParseEnc
	}
	Pk_u, err := curve.FromString(segmentFormat.Pk_u)
	if err != nil {
		log.Println("[FromRemoveLiquiditySegmentJSON] err info:", err)
		return nil, ErrParsePoint
	}
	Sk, isValid := new(big.Int).SetString(segmentFormat.Sk_u, 10)
	if !isValid {
		log.Println("[FromRemoveLiquiditySegmentJSON] err info:", ErrParseBigInt)
		return nil, ErrParseBigInt
	}
	C_fee, err := twistedElgamal.FromString(segmentFormat.C_fee)
	if err != nil {
		log.Println("[FromRemoveLiquiditySegmentJSON] err info:", err)
		return nil, ErrParseEnc
	}
	swapSegment := &RemoveLiquiditySegment{
		PairIndex:     uint32(segmentFormat.PairIndex),
		AccountIndex:  uint32(segmentFormat.AccountIndex),
		C_u_LP:        C_u_LP,
		Pk_u:          Pk_u,
		B_LP:          uint64(segmentFormat.B_LP),
		Delta_LP:      uint64(segmentFormat.Delta_LP),
		MinB_A_Delta:  uint64(segmentFormat.MinB_A_Delta),
		MinB_B_Delta:  uint64(segmentFormat.MinB_B_Delta),
		AssetAId:      uint32(segmentFormat.AssetAId),
		AssetBId:      uint32(segmentFormat.AssetBId),
		Sk_u:          Sk,
		C_fee:         C_fee,
		B_fee:         uint64(segmentFormat.B_fee),
		GasFeeAssetId: uint32(segmentFormat.GasFeeAssetId),
		GasFee:        uint64(segmentFormat.GasFee),
	}
	return swapSegment, Success
}

type RemoveLiquidityTxInfo struct {
	PairIndex                  uint32
	AccountIndex               uint32
	AssetAId, AssetBId         uint32
	MinB_A_Delta, MinB_B_Delta uint64
	Delta_LP                   uint64
	// gas part
	GasFeeAssetId uint32
	GasFee        uint64
	Proof         string
}
