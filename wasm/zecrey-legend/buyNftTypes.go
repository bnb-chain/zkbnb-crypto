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
	"hash"
	"log"
)

type BuyNftSegmentFormat struct {
	AccountIndex         int64
	OwnerAccountIndex    int64
	NftIndex             int64
	AssetId              int64
	AssetAmount          int64
	TreasuryFeeRate      int64
	TreasuryAccountIndex int64
	GasAccountIndex      int64
	GasFeeAssetId        int64
	GasFeeAssetAmount    int64
	Nonce                int64 `json:"nonce"`
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
	txInfo = &BuyNftTxInfo{
		AccountIndex:         uint32(segmentFormat.AccountIndex),
		OwnerAccountIndex:    uint32(segmentFormat.OwnerAccountIndex),
		NftIndex:             uint32(segmentFormat.NftIndex),
		AssetId:              uint32(segmentFormat.AssetId),
		AssetAmount:          uint64(segmentFormat.AssetAmount),
		TreasuryFeeRate:      uint32(segmentFormat.TreasuryFeeRate),
		TreasuryAccountIndex: uint32(segmentFormat.TreasuryAccountIndex),
		GasAccountIndex:      uint32(segmentFormat.GasAccountIndex),
		GasFeeAssetId:        uint32(segmentFormat.GasFeeAssetId),
		GasFeeAssetAmount:    uint64(segmentFormat.GasFeeAssetAmount),
		Nonce:                uint64(segmentFormat.Nonce),
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
	AccountIndex         uint32
	OwnerAccountIndex    uint32
	NftIndex             uint32
	AssetId              uint32
	AssetAmount          uint64
	TreasuryFeeRate      uint32
	TreasuryAccountIndex uint32
	GasAccountIndex      uint32
	GasFeeAssetId        uint32
	GasFeeAssetAmount    uint64
	Nonce                uint64
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
	writeUint64IntoBuf(&buf, uint64(txInfo.AccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.OwnerAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.NftIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.TreasuryAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.TreasuryFeeRate))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.Nonce))
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
