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

type GenericTransferSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	ToAccountIndex    int64  `json:"to_account_index"`
	ToAccountName     string `json:"to_account_name"`
	AssetId           int64  `json:"asset_id"`
	AssetAmount       int64  `json:"asset_amount"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount int64  `json:"gas_fee_asset_amount"`
	CallData          string `json:"call_data"`
	NftIndex          int    `json:"nft_index"`
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
		FromAccountIndex:  uint32(segmentFormat.FromAccountIndex),
		ToAccountIndex:    uint32(segmentFormat.ToAccountIndex),
		ToAccountName:     segmentFormat.ToAccountName,
		AssetId:           uint32(segmentFormat.AssetId),
		AssetAmount:       uint64(segmentFormat.AssetAmount),
		GasAccountIndex:   uint32(segmentFormat.GasAccountIndex),
		GasFeeAssetId:     uint32(segmentFormat.GasFeeAssetId),
		GasFeeAssetAmount: uint64(segmentFormat.GasFeeAssetAmount),
		CallData:          segmentFormat.CallData,
		CallDataHash:      nil,
		NftIndex:          segmentFormat.NftIndex,
		Nonce:             uint64(segmentFormat.Nonce),
		Sig:               nil,
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
	FromAccountIndex  uint32
	ToAccountIndex    uint32
	ToAccountName     string
	AssetId           uint32
	AssetAmount       uint64
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
	CallData          string
	CallDataHash      []byte
	NftIndex          int
	Nonce             uint64
	Sig               []byte
}

func ComputeGenericTransferMsgHash(txInfo *GenericTransferTxInfo, hFunc hash.Hash) (msgHash []byte) {
	hFunc.Reset()
	var buf bytes.Buffer
	writeUint64IntoBuf(&buf, uint64(txInfo.FromAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.ToAccountIndex))
	accountNameBytes := AccountNameToFullByte(txInfo.ToAccountName)
	buf.Write(accountNameBytes)
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetAmount))
	buf.Write(txInfo.CallDataHash)
	writeUint64IntoBuf(&buf, uint64(txInfo.NftIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.Nonce))
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}
