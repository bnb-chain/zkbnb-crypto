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

type SetNftPriceSegmentFormat struct {
	AccountIndex      int64  `json:"account_index"`
	NftAssetId        int64  `json:"nft_asset_id"`
	NftIndex          int64  `json:"nft_index"`
	NftContentHash    string `json:"nft_content_hash"`
	AssetId           int64  `json:"asset_id"`
	AssetAmount       string `json:"asset_amount"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount int64  `json:"gas_fee_asset_amount"`
	Nonce             int64  `json:"nonce"`
}

/*
	ConstructSetNftPriceTxInfo: construct set nft price tx, sign txInfo
*/
func ConstructSetNftPriceTxInfo(sk *PrivateKey, segmentStr string) (txInfo *SetNftPriceTxInfo, err error) {
	var segmentFormat *SetNftPriceSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructSetNftPriceTxInfo] err info:", err)
		return nil, err
	}
	assetAmount, err := StringToBigInt(segmentFormat.AssetAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	txInfo = &SetNftPriceTxInfo{
		AccountIndex:      segmentFormat.AccountIndex,
		NftAssetId:        segmentFormat.NftAssetId,
		NftIndex:          segmentFormat.NftIndex,
		NftContentHash:    common.FromHex(segmentFormat.NftContentHash),
		AssetId:           segmentFormat.AssetId,
		AssetAmount:       assetAmount,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: segmentFormat.GasFeeAssetAmount,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash := ComputeSetNftPriceMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructSetNftPriceTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type SetNftPriceTxInfo struct {
	AccountIndex      int64
	NftAssetId        int64
	NftIndex          int64
	NftContentHash    []byte
	AssetId           int64
	AssetAmount       *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
	Nonce             int64
	Sig               []byte
}

func ComputeSetNftPriceMsgHash(txInfo *SetNftPriceTxInfo, hFunc hash.Hash) (msgHash []byte) {
	hFunc.Reset()
	/*
		hFunc.Write(
			tx.AccountIndex,
			tx.NftIndex,
			tx.AssetId,
			tx.AssetAmount,
			tx.GasAccountIndex,
			tx.GasFeeAssetId,
			tx.GasFeeAssetAmount,
		)
		hFunc.Write(nonce)
	*/
	var buf bytes.Buffer
	writeInt64IntoBuf(&buf, txInfo.AccountIndex)
	writeInt64IntoBuf(&buf, txInfo.NftAssetId)
	writeInt64IntoBuf(&buf, txInfo.NftIndex)
	buf.Write(txInfo.NftContentHash)
	writeInt64IntoBuf(&buf, txInfo.AssetId)
	writeBigIntIntoBuf(&buf, txInfo.AssetAmount)
	writeInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetAmount)
	writeInt64IntoBuf(&buf, txInfo.Nonce)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
