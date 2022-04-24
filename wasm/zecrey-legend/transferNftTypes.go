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

package zecrey_legend

import (
	"bytes"
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"log"
)

type TransferNftSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	ToAccountIndex    int64  `json:"to_account_index"`
	NftIndex          int64  `json:"nft_index"`
	NftAssetId        int64  `json:"nft_asset_id"`
	NftContentHash    string `json:"nft_content_hash"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount int64  `json:"gas_fee_asset_amount"`
	CallData          string `json:"call_data"`
	Nonce             int64  `json:"nonce"`
}

/*
	ConstructTransferNftTxInfo: construct transfer nft tx, sign txInfo
*/
func ConstructTransferNftTxInfo(sk *PrivateKey, segmentStr string) (txInfo *TransferNftTxInfo, err error) {
	var segmentFormat *TransferNftSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructTransferNftTxInfo] err info:", err)
		return nil, err
	}
	txInfo = &TransferNftTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		ToAccountIndex:    segmentFormat.ToAccountIndex,
		NftAssetId:        segmentFormat.NftAssetId,
		NftIndex:          segmentFormat.NftIndex,
		NftContentHash:    segmentFormat.NftContentHash,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: segmentFormat.GasFeeAssetAmount,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute msg hash
	hFunc := mimc.NewMiMC()
	hFunc.Write([]byte(txInfo.CallData))
	callDataHash := hFunc.Sum(nil)
	txInfo.CallDataHash = callDataHash
	hFunc.Reset()
	msgHash := ComputeTransferNftMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructTransferNftTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type TransferNftTxInfo struct {
	FromAccountIndex  int64
	ToAccountIndex    int64
	NftAssetId        int64
	NftIndex          int64
	NftContentHash    string
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
	CallData          string
	CallDataHash      []byte
	Nonce             int64
	Sig               []byte
}

func ComputeTransferNftMsgHash(txInfo *TransferNftTxInfo, hFunc hash.Hash) (msgHash []byte) {
	hFunc.Reset()
	var buf bytes.Buffer
	writeInt64IntoBuf(&buf, txInfo.FromAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.ToAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.NftAssetId)
	writeInt64IntoBuf(&buf, txInfo.NftIndex)
	buf.Write(common.FromHex(txInfo.NftContentHash))
	writeInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetAmount)
	buf.Write(txInfo.CallDataHash)
	writeInt64IntoBuf(&buf, txInfo.Nonce)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
