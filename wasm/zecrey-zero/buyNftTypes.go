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

package zecrey_zero

import (
	"encoding/json"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"log"
	"math/big"
)

/*
	BuyNftSegment: which is used to construct buy nft proof
*/
type BuyNftSegment struct {
	AccountIndex      uint32
	C                 *ElGamalEnc
	Pk                *Point
	B                 uint64
	Sk                *big.Int
	OwnerAccountIndex uint32
	NftIndex          uint32
	AssetId           uint32
	AssetAmount       uint64
	FeeRate           uint32
	// fee part
	C_fee         *ElGamalEnc
	B_fee         uint64
	GasFeeAssetId uint32
	GasFee        uint64
}

/*
	BuyNftSegmentFormat: format version of BuyNftSegment
*/
type BuyNftSegmentFormat struct {
	// account index
	AccountIndex int `json:"account_index"`
	// encryption of the balance
	C string `json:"c"`
	// public key
	Pk string `json:"pk"`
	// balance
	B int64 `json:"b"`
	// private key
	Sk string `json:"sk"`
	// owner index
	OwnerAccountIndex int   `json:"owner_account_index"`
	NftIndex          int   `json:"nft_index"`
	AssetId           int   `json:"asset_id"`
	AssetAmount       int64 `json:"asset_amount"`
	FeeRate           int   `json:"fee_rate"`
	// fee part
	// encryption of balance of the gas fee asset
	C_fee string `json:"c_fee"`
	// balance of gas fee asset
	B_fee int64 `json:"b_fee"`
	// gas fee asset id
	GasFeeAssetId int `json:"gas_fee_asset_id"`
	// gas fee
	GasFee int64 `json:"gas_fee"`
}

func FromBuyNftSegmentJSON(segmentStr string) (*BuyNftSegment, string) {
	var segmentFormat *BuyNftSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[FromBuyNftSegmentJSON] err info:", err)
		return nil, ErrUnmarshal
	}
	if segmentFormat.C == "" || segmentFormat.Pk == "" ||
		segmentFormat.Sk == "" {
		log.Println("[FromBuyNftSegmentJSON] invalid params")
		return nil, ErrInvalidWithdrawParams
	}
	if segmentFormat.OwnerAccountIndex == segmentFormat.AccountIndex {
		return nil, "[FromBuyNftSegmentJSON] unable to buy your nft"
	}
	// verify params
	if segmentFormat.AccountIndex < 0 || segmentFormat.B < 0 ||
		segmentFormat.AssetId < 0 || segmentFormat.AssetAmount < 0 || segmentFormat.B_fee < 0 ||
		segmentFormat.GasFeeAssetId < 0 || segmentFormat.GasFee < 0 {
		return nil, ErrInvalidWithdrawParams
	}
	C, err := twistedElgamal.FromString(segmentFormat.C)
	if err != nil {
		log.Println("[FromBuyNftSegmentJSON] invalid params")
		return nil, ErrParseEnc
	}
	Pk, err := curve.FromString(segmentFormat.Pk)
	if err != nil {
		log.Println("[FromBuyNftSegmentJSON] invalid params")
		return nil, ErrParsePoint
	}
	Sk, isValid := new(big.Int).SetString(segmentFormat.Sk, 10)
	if !isValid {
		log.Println("[FromBuyNftSegmentJSON] invalid params")
		return nil, ErrParseBigInt
	}
	C_fee, err := twistedElgamal.FromString(segmentFormat.C_fee)
	if err != nil {
		log.Println("[FromBuyNftSegmentJSON] invalid params")
		return nil, ErrParseEnc
	}
	segment := &BuyNftSegment{
		AccountIndex:      uint32(segmentFormat.AccountIndex),
		C:                 C,
		Pk:                Pk,
		B:                 uint64(segmentFormat.B),
		Sk:                Sk,
		OwnerAccountIndex: uint32(segmentFormat.OwnerAccountIndex),
		NftIndex:          uint32(segmentFormat.NftIndex),
		AssetId:           uint32(segmentFormat.AssetId),
		AssetAmount:       uint64(segmentFormat.AssetAmount),
		FeeRate:           uint32(segmentFormat.FeeRate),
		C_fee:             C_fee,
		B_fee:             uint64(segmentFormat.B_fee),
		GasFeeAssetId:     uint32(segmentFormat.GasFeeAssetId),
		GasFee:            uint64(segmentFormat.GasFee),
	}
	return segment, Success
}

type BuyNftTxInfo struct {
	// zecrey-legend index
	AccountIndex uint32
	// nft owner
	OwnerAccountIndex uint32
	// nft index
	NftIndex uint32
	// nft asset id
	AssetId uint32
	// nft price
	AssetAmount uint64
	FeeRate     uint32
	// gas fee part
	GasFeeAssetId uint32
	GasFee        uint64
	// withdraw proof
	Proof string
}
