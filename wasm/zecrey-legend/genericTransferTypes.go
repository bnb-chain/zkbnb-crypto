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
	"math/big"
)

type GenericTransferSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	ToAccountIndex    int64  `json:"to_account_index"`
	ToAccountName     string `json:"to_account_name"`
	AssetId           int64  `json:"asset_id"`
	AssetAmount       string `json:"asset_amount"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount int64  `json:"gas_fee_asset_amount"`
	CallData          string `json:"call_data"`
	NftAssetId        int64  `json:"nft_asset_id"`
	NftIndex          int64  `json:"nft_index"`
	NftContentHash    string `json:"nft_content_hash"`
	Nonce             int64  `json:"nonce"`
}

/*
	ConstructGenericTransferTxInfo: construct generic transfer tx, sign txInfo
*/
func ConstructGenericTransferTxInfo(sk *PrivateKey, segmentStr string) (txInfo *GenericTransferTxInfo, err error) {
	var segmentFormat *GenericTransferSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructGenericTransferTxInfo] err info:", err)
		return nil, err
	}
	txInfo = &GenericTransferTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		ToAccountIndex:    segmentFormat.ToAccountIndex,
		ToAccountName:     segmentFormat.ToAccountName,
		AssetId:           segmentFormat.AssetId,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: segmentFormat.GasFeeAssetAmount,
		CallData:          segmentFormat.CallData,
		CallDataHash:      nil,
		NftAssetId:        segmentFormat.NftAssetId,
		NftIndex:          segmentFormat.NftIndex,
		NftContentHash:    segmentFormat.NftContentHash,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	if txInfo.AssetId != -1 {
		assetAmount, err := StringToBigInt(segmentFormat.AssetAmount)
		if err != nil {
			log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
			return nil, err
		}
		txInfo.AssetAmount = assetAmount
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	hFunc.Write([]byte(txInfo.CallData))
	callDataHash := hFunc.Sum(nil)
	txInfo.CallDataHash = callDataHash
	hFunc.Reset()
	// compute msg hash
	msgHash := ComputeGenericTransferMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructGenericTransferTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type GenericTransferTxInfo struct {
	FromAccountIndex  int64
	ToAccountIndex    int64
	ToAccountName     string
	AssetId           int64
	AssetAmount       *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
	CallData          string
	CallDataHash      []byte
	NftAssetId        int64
	NftIndex          int64
	NftContentHash    string
	Nonce             int64
	Sig               []byte
}

func ComputeGenericTransferMsgHash(txInfo *GenericTransferTxInfo, hFunc hash.Hash) (msgHash []byte) {
	hFunc.Reset()
	var buf bytes.Buffer
	writeInt64IntoBuf(&buf, txInfo.FromAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.ToAccountIndex)
	accountNameBytes := PaddingStringToBytes32(txInfo.ToAccountName)
	buf.Write(accountNameBytes)
	writeInt64IntoBuf(&buf, txInfo.AssetId)
	writeBigIntIntoBuf(&buf, txInfo.AssetAmount)
	writeInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetAmount)
	buf.Write(txInfo.CallDataHash)
	writeInt64IntoBuf(&buf, txInfo.NftAssetId)
	writeInt64IntoBuf(&buf, txInfo.NftIndex)
	buf.Write(common.FromHex(txInfo.NftContentHash))
	writeInt64IntoBuf(&buf, txInfo.Nonce)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
