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

package src

import (
	"encoding/json"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"log"
	"math/big"
)

/*
	SwapSegment: which is used to construct swap proof
*/
type SwapSegment struct {
	PairIndex          uint32
	AccountIndex       uint32
	C_uA               *ElGamalEnc
	Pk_u, Pk_treasury  *Point
	AssetAId, AssetBId uint32
	B_A_Delta, B_u_A   uint64
	MinB_B_Delta       uint64
	FeeRate            uint32
	TreasuryRate       uint32
	Sk_u               *big.Int
	// fee part
	C_fee         *ElGamalEnc
	B_fee         uint64
	GasFeeAssetId uint32
	GasFee        uint64
}

/*
	SwapSegmentFormat: format version of SwapSegment
*/
type SwapSegmentFormat struct {
	// pair index
	PairIndex    int    `json:"pair_index"`
	// account index
	AccountIndex int    `json:"account_index"`
	// encryption of the balance of asset A
	C_uA         string `json:"c_u_a"`
	// user public key
	Pk_u         string `json:"pk_u"`
	// system treasury account public key
	Pk_treasury  string `json:"pk_treasury"`
	// asset a id
	AssetAId     int    `json:"asset_a_id"`
	// asset b id
	AssetBId     int    `json:"asset_b_id"`
	// swap amount for asset a
	B_A_Delta    int64  `json:"b_a_delta"`
	// balance for asset a
	B_u_A        int64  `json:"b_u_a"`
	// equal to B * (1 - slippage), B gets from the layer-2
	MinB_B_Delta int64  `json:"min_b_b_delta"`
	// fee rate, gets from layer-2
	FeeRate      int    `json:"fee_rate"`
	// treasury rate gets from layer-2
	TreasuryRate int    `json:"treasury_rate"`
	// private key
	Sk_u         string `json:"sk_u"`
	// fee part
	C_fee         string `json:"c_fee"`
	B_fee         int64  `json:"b_fee"`
	GasFeeAssetId int    `json:"gas_fee_asset_id"`
	GasFee        int64  `json:"gas_fee"`
}

func FromSwapSegmentJSON(segmentStr string) (*SwapSegment, string) {
	var segmentFormat *SwapSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[FromSwapSegmentJSON] err info: ", err)
		return nil, ErrUnmarshal
	}
	if segmentFormat.C_uA == "" || segmentFormat.C_fee == "" || segmentFormat.Pk_u == "" || segmentFormat.Pk_treasury == "" ||
		segmentFormat.Sk_u == "" {
		log.Println("[FromSwapSegmentJSON] err info: ", ErrInvalidSwapParams)
		return nil, ErrInvalidSwapParams
	}
	// verify params
	if segmentFormat.PairIndex < 0 || segmentFormat.AccountIndex < 0 || segmentFormat.AssetAId < 0 ||
		segmentFormat.AssetBId < 0 || segmentFormat.AssetAId == segmentFormat.AssetBId ||
		segmentFormat.B_A_Delta < 0 || segmentFormat.B_u_A < 0 || segmentFormat.B_u_A < segmentFormat.B_A_Delta ||
		segmentFormat.MinB_B_Delta < 0 || segmentFormat.FeeRate < 0 || segmentFormat.TreasuryRate < 0 || segmentFormat.FeeRate < segmentFormat.TreasuryRate ||
		segmentFormat.B_fee < 0 || segmentFormat.GasFeeAssetId < 0 || segmentFormat.GasFee < 0 {
		log.Println("[FromSwapSegmentJSON] err info: ", ErrInvalidSwapParams)
		return nil, ErrInvalidSwapParams
	}
	C_uA, err := twistedElgamal.FromString(segmentFormat.C_uA)
	if err != nil {
		log.Println("[FromSwapSegmentJSON] err info: ", err)
		return nil, ErrParseEnc
	}
	Pk_u, err := curve.FromString(segmentFormat.Pk_u)
	if err != nil {
		log.Println("[FromSwapSegmentJSON] err info: ", err)
		return nil, ErrParsePoint
	}
	Pk_treasury, err := curve.FromString(segmentFormat.Pk_treasury)
	if err != nil {
		log.Println("[FromSwapSegmentJSON] err info: ", err)
		return nil, ErrParsePoint
	}
	Sk_u, isValid := new(big.Int).SetString(segmentFormat.Sk_u, 10)
	if !isValid {
		log.Println("[FromSwapSegmentJSON] err info: ", ErrParseBigInt)
		return nil, ErrParseBigInt
	}
	C_fee, err := twistedElgamal.FromString(segmentFormat.C_fee)
	if err != nil {
		log.Println("[FromSwapSegmentJSON] err info: ", err)
		return nil, ErrParseEnc
	}
	swapSegment := &SwapSegment{
		PairIndex:     uint32(segmentFormat.PairIndex),
		AccountIndex:  uint32(segmentFormat.AccountIndex),
		C_uA:          C_uA,
		Pk_u:          Pk_u,
		Pk_treasury:   Pk_treasury,
		AssetAId:      uint32(segmentFormat.AssetAId),
		AssetBId:      uint32(segmentFormat.AssetBId),
		B_A_Delta:     uint64(segmentFormat.B_A_Delta),
		B_u_A:         uint64(segmentFormat.B_u_A),
		MinB_B_Delta:  uint64(segmentFormat.MinB_B_Delta),
		FeeRate:       uint32(segmentFormat.FeeRate),
		TreasuryRate:  uint32(segmentFormat.TreasuryRate),
		Sk_u:          Sk_u,
		C_fee:         C_fee,
		B_fee:         uint64(segmentFormat.B_fee),
		GasFeeAssetId: uint32(segmentFormat.GasFeeAssetId),
		GasFee:        uint64(segmentFormat.GasFee),
	}
	return swapSegment, Success
}

type SwapTxInfo struct {
	// pair index
	PairIndex uint32
	// account index
	AccountIndex uint32
	AssetAId     uint32
	AssetBId     uint32
	// gas fee part
	GasFeeAssetId uint32
	GasFee        uint64
	FeeRate       uint32
	TreasuryRate  uint32
	// swap amount
	B_A_Delta    uint64
	MinB_B_Delta uint64
	// swap proof
	Proof string
}
