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

package test

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ethereum/go-ethereum/common"
	"testing"
)

func TestBuyNft(t *testing.T) {
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
		OwnerAccountIndex int    `json:"owner_account_index"`
		NftContentHash    string `json:"nft_content_hash"`
		AssetId           int    `json:"asset_id"`
		AssetAmount       int64  `json:"asset_amount"`
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
	hFunc := mimc.NewMiMC()
	hFunc.Write([]byte("test"))
	contentHash := hFunc.Sum(nil)
	format := BuyNftSegmentFormat{
		AccountIndex:      0,
		C:                 "lQn5GcmB0DLr2VvC8ttJK9pkjZESu0aUfBeiICge6Ae5GDbfLc8QwHpFeIBdvzbv2dMGIlVF7lkx05720w0psA==",
		Pk:                "RrJYKK4xRJBkyuk9sFtTjmtBer7lhEwElxIRvDjFrKs=",
		B:                 8,
		Sk:                "475102078831139334017978367390533535565844015034988513555777843897424109597",
		OwnerAccountIndex: 4,
		NftContentHash:    common.Bytes2Hex(contentHash),
		AssetId:           2,
		AssetAmount:       5,
		C_fee:             "lQn5GcmB0DLr2VvC8ttJK9pkjZESu0aUfBeiICge6Ac2UXTOz5146FGzJNLyFa4fhebya39lHPNvAXCS+Shpjw==",
		B_fee:             10,
		GasFeeAssetId:     1,
		GasFee:            1,
	}
	segmentBytes, _ := json.Marshal(format)
	fmt.Println(string(segmentBytes))
}
