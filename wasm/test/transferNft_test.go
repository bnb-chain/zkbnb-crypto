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

func TestTransferNft(t *testing.T) {
	type TransferNftSegmentFormat struct {
		// account index
		AccountIndex int `json:"account_index"`
		// public key
		Pk string `json:"pk"`
		// private key
		Sk string `json:"sk"`
		// common input part
		NftContentHash       string `json:"nft_content_hash"`
		ReceiverAccountIndex int    `json:"receiver_account_index"`
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
	format := TransferNftSegmentFormat{
		AccountIndex:         0,
		Pk:                   "4uA+cBJAeV3Fw6VcZRi6GxSHRm06tgWZ7r9gkiDzNpc=",
		Sk:                   "2073942362777190894649839587911172153339757863207512928340352386750181764118",
		NftContentHash:       common.Bytes2Hex(contentHash),
		ReceiverAccountIndex: 1,
		C_fee:                "/IfGU/5r2Jdww4Q/Z28eGO2bQsJBTvyzmy9Qz1v6mJDErMQ927/XInUDC/45+7zwXRujNDsjPK0zAaT0bVOiDg==",
		B_fee:                10,
		GasFeeAssetId:        1,
		GasFee:               1,
	}
	segmentBytes, _ := json.Marshal(format)
	fmt.Println(string(segmentBytes))
}
