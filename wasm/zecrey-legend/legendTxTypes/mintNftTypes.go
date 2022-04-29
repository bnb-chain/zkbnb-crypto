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

package legendTxTypes

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
	NftAttributes       string `json:"nft_attributes"`
	NftCollectionId     int64  `json:"nft_collection_id"`
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
		CreatorAccountIndex: segmentFormat.CreatorAccountIndex,
		ToAccountIndex:      segmentFormat.ToAccountIndex,
		NftIndex:            segmentFormat.NftIndex,
		NftContentHash:      segmentFormat.NftContentHash,
		NftName:             segmentFormat.NftName,
		NftIntroduction:     segmentFormat.NftIntroduction,
		NftAttributes:       segmentFormat.NftAttributes,
		NftCollectionId:     segmentFormat.NftCollectionId,
		GasAccountIndex:     segmentFormat.GasAccountIndex,
		GasFeeAssetId:       segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount:   segmentFormat.GasFeeAssetAmount,
		Nonce:               segmentFormat.Nonce,
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
	CreatorAccountIndex int64
	ToAccountIndex      int64
	ToAccountName       string
	NftIndex            int64
	NftContentHash      string
	NftName             string
	NftIntroduction     string
	NftAttributes       string
	NftCollectionId     int64
	GasAccountIndex     int64
	GasFeeAssetId       int64
	GasFeeAssetAmount   int64
	Nonce               int64
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
			tx.GasAccountIndex,
			tx.GasFeeAssetId,
			tx.GasFeeAssetAmount,
		)
		hFunc.Write(nonce)
	*/
	var buf bytes.Buffer
	WriteInt64IntoBuf(&buf, txInfo.CreatorAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.ToAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.NftIndex)
	buf.Write(common.FromHex(txInfo.NftContentHash))
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetAmount)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
