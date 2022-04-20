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

type MintNftSegmentFormat struct {
	CreatorAccountIndex int64  `json:"creator_account_index"`
	ToAccountIndex      int64  `json:"to_account_index"`
	NftIndex            int64  `json:"nft_index"`
	NftContentHash      string `json:"nft_content_hash"`
	NftName             string `json:"nft_name"`
	NftIntroduction     string `json:"nft_introduction"`
	NftCollectionId     int64  `json:"nft_collection_id"`
	NftAttributes       string `json:"nft_attributes"`
	AssetId             int64  `json:"asset_id"`
	AssetAmount         int64  `json:"asset_amount"`
	GasAccountIndex     int64  `json:"gas_account_index"`
	GasFeeAssetId       int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount   int64  `json:"gas_fee_asset_amount"`
	Nonce               int64  `json:"nonce"`
}

/*
	ConstructMintNftTxInfo: construct mint nft tx, sign txInfo
*/
func ConstructMintNftTxInfo(sk *PrivateKey, segmentStr string) (txInfo *MintNftTxInfo, err error) {
	var segmentFormat *MintNftSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructMintNftTxInfo] err info:", err)
		return nil, err
	}
	txInfo = &MintNftTxInfo{
		CreatorAccountIndex: uint32(segmentFormat.CreatorAccountIndex),
		ToAccountIndex:      uint32(segmentFormat.ToAccountIndex),
		NftIndex:            uint64(segmentFormat.NftIndex),
		NftContentHash:      segmentFormat.NftContentHash,
		NftCollectionId:     uint32(segmentFormat.NftCollectionId),
		AssetId:             uint32(segmentFormat.AssetId),
		AssetAmount:         uint64(segmentFormat.AssetAmount),
		GasAccountIndex:     uint32(segmentFormat.GasAccountIndex),
		GasFeeAssetId:       uint32(segmentFormat.GasFeeAssetId),
		GasFeeAssetAmount:   uint64(segmentFormat.GasFeeAssetAmount),
		Nonce:               uint64(segmentFormat.Nonce),
		Sig:                 nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash := ComputeMintNftMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructMintNftTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type MintNftTxInfo struct {
	CreatorAccountIndex uint32
	ToAccountIndex      uint32
	NftAssetId          uint32
	NftIndex            uint64
	NftContentHash      string
	NftCollectionId     uint32
	AssetId             uint32
	AssetAmount         uint64
	GasAccountIndex     uint32
	GasFeeAssetId       uint32
	GasFeeAssetAmount   uint64
	Nonce               uint64
	Sig                 []byte
}

func ComputeMintNftMsgHash(txInfo *MintNftTxInfo, hFunc hash.Hash) (msgHash []byte) {
	hFunc.Reset()
	/*
		hFunc.Write(
			tx.CreatorAccountIndex,
			tx.ToAccountIndex,
			tx.NftIndex,
			tx.NftContentHash,
			tx.AssetId,
			tx.AssetAmount,
			tx.GasAccountIndex,
			tx.GasFeeAssetId,
			tx.GasFeeAssetAmount,
		)
		hFunc.Write(nonce)
	*/
	var buf bytes.Buffer
	writeUint64IntoBuf(&buf, uint64(txInfo.CreatorAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.ToAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.NftIndex))
	buf.Write(common.FromHex(txInfo.NftContentHash))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.Nonce))
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
