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

type BuyNftSegmentFormat struct {
	AccountIndex         int64  `json:"account_index"`
	OwnerAccountIndex    int64  `json:"owner_account_index"`
	NftIndex             int64  `json:"nft_index"`
	NftContentHash       string `json:"nft_content_hash"`
	AssetId              int64  `json:"asset_id"`
	AssetAmount          string `json:"asset_amount"`
	TreasuryFeeRate      int64  `json:"treasury_fee_rate"`
	TreasuryAccountIndex int64  `json:"treasury_account_index"`
	GasAccountIndex      int64  `json:"gas_account_index"`
	GasFeeAssetId        int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount    int64  `json:"gas_fee_asset_amount"`
	Nonce                int64  `json:"nonce"`
}

/*
	ConstructBuyNftTxInfo: construct buy nft tx, sign txInfo
*/
func ConstructBuyNftTxInfo(sk *PrivateKey, segmentStr string) (txInfo *BuyNftTxInfo, err error) {
	var segmentFormat *BuyNftSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] err info:", err)
		return nil, err
	}
	assetAmount, err := StringToBigInt(segmentFormat.AssetAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	txInfo = &BuyNftTxInfo{
		AccountIndex:         segmentFormat.AccountIndex,
		OwnerAccountIndex:    segmentFormat.OwnerAccountIndex,
		NftIndex:             segmentFormat.NftIndex,
		NftContentHash:       segmentFormat.NftContentHash,
		AssetId:              segmentFormat.AssetId,
		AssetAmount:          assetAmount,
		TreasuryFeeRate:      segmentFormat.TreasuryFeeRate,
		TreasuryAccountIndex: segmentFormat.TreasuryAccountIndex,
		GasAccountIndex:      segmentFormat.GasAccountIndex,
		GasFeeAssetId:        segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount:    segmentFormat.GasFeeAssetAmount,
		Nonce:                segmentFormat.Nonce,
		Sig:                  nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash := ComputeBuyNftMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type BuyNftTxInfo struct {
	AccountIndex         int64
	OwnerAccountIndex    int64
	NftIndex             int64
	NftContentHash       string
	AssetId              int64
	AssetAmount          *big.Int
	TreasuryFeeRate      int64
	TreasuryAccountIndex int64
	GasAccountIndex      int64
	GasFeeAssetId        int64
	GasFeeAssetAmount    int64
	Nonce                int64
	Sig                  []byte
}

func ComputeBuyNftMsgHash(txInfo *BuyNftTxInfo, hFunc hash.Hash) (msgHash []byte) {
	hFunc.Reset()
	/*
		hFunc.Write(
			tx.AccountIndex,
			tx.OwnerAccountIndex,
			tx.NftIndex,
			tx.AssetId,
			tx.AssetAmount,
			tx.TreasuryAccountIndex,
			tx.TreasuryFeeRate,
			tx.GasAccountIndex,
			tx.GasFeeAssetId,
			tx.GasFeeAssetAmount,
		)
		hFunc.Write(nonce)
	*/
	var buf bytes.Buffer
	writeInt64IntoBuf(&buf, txInfo.AccountIndex)
	writeInt64IntoBuf(&buf, txInfo.OwnerAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.NftIndex)
	buf.Write(common.FromHex(txInfo.NftContentHash))
	writeInt64IntoBuf(&buf, txInfo.AssetId)
	writeBigIntIntoBuf(&buf, txInfo.AssetAmount)
	writeInt64IntoBuf(&buf, txInfo.TreasuryAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.TreasuryFeeRate)
	writeInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	writeInt64IntoBuf(&buf, txInfo.GasFeeAssetAmount)
	writeInt64IntoBuf(&buf, txInfo.Nonce)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
