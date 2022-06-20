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
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"log"
	"math/big"
)

type UnlockSegment struct {
	ChainId, AccountIndex, AssetId uint32
	Balance, DeltaAmount           uint64
	Sk                             *big.Int
	// fee part
	C_fee         *ElGamalEnc
	B_fee         uint64
	GasFeeAssetId uint32
	GasFee        uint64
}

type UnlockSegmentFormat struct {
	// chain id
	ChainId int `json:"chain_id"`
	// account index
	AccountIndex int `json:"account_index"`
	// asset id
	AssetId int `json:"asset_id"`
	// balance
	Balance int64 `json:"balance"`
	// unlock amount
	DeltaAmount int64 `json:"delta_amount"`
	// private key
	Sk string `json:"sk"`
	// fee part
	// encryption of the balance of the gas fee
	C_fee string `json:"c_fee"`
	// gas fee balance
	B_fee int64 `json:"b_fee"`
	// gas fee asset id
	GasFeeAssetId int `json:"gas_fee_asset_id"`
	// gas fee
	GasFee int64 `json:"gas_fee"`
}

func FromUnlockSegmentJSON(segmentStr string) (*UnlockSegment, string) {
	var segmentFormat *UnlockSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[FromUnlockSegmentJSON] err info: ", err)
		return nil, ErrUnmarshal
	}
	// verify params
	if segmentFormat.ChainId < 0 || segmentFormat.AccountIndex < 0 || segmentFormat.AssetId < 0 || segmentFormat.Balance < 0 ||
		segmentFormat.DeltaAmount < 0 || segmentFormat.B_fee < 0 || segmentFormat.GasFeeAssetId < 0 || segmentFormat.GasFee < 0 {
		log.Println("[FromUnlockSegmentJSON] err info: ", ErrInvalidUnlockParams)
		return nil, ErrInvalidUnlockParams
	}
	var segment *UnlockSegment
	var (
		Sk      *big.Int
		isValid bool
		C_fee   *ElGamalEnc
	)
	Sk, isValid = new(big.Int).SetString(segmentFormat.Sk, 10)
	if !isValid {
		log.Println("[FromUnlockSegmentJSON] err info:", ErrInvalidUnlockParams)
		return nil, ErrInvalidUnlockParams
	}
	C_fee, err = twistedElgamal.FromString(segmentFormat.C_fee)
	if err != nil {
		log.Println("[FromUnlockSegmentJSON] err info:", ErrParseEnc)
		return nil, ErrParseEnc
	}
	segment = &UnlockSegment{
		ChainId:       uint32(segmentFormat.ChainId),
		AccountIndex:  uint32(segmentFormat.AccountIndex),
		AssetId:       uint32(segmentFormat.AssetId),
		Balance:       uint64(segmentFormat.Balance),
		DeltaAmount:   uint64(segmentFormat.DeltaAmount),
		Sk:            Sk,
		C_fee:         C_fee,
		B_fee:         uint64(segmentFormat.B_fee),
		GasFeeAssetId: uint32(segmentFormat.GasFeeAssetId),
		GasFee:        uint64(segmentFormat.GasFee),
	}
	return segment, Success
}

type UnlockTxInfo struct {
	ChainId       uint32
	AccountIndex  uint32
	AssetId       uint32
	GasFeeAssetId uint32
	GasFee        uint64
	DeltaAmount   uint64
	Proof         string
}
