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
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"hash"
	"log"
	"math/big"
)

type TransferSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	ToAccountIndex    int64  `json:"to_account_index"`
	ToAccountNameHash string `json:"to_account_name"`
	AssetId           int64  `json:"asset_id"`
	AssetAmount       string `json:"asset_amount"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	Memo              string `json:"memo"`
	CallData          string `json:"call_data"`
	ExpiredAt         int64  `json:"expired_at"`
	Nonce             int64  `json:"nonce"`
}

/*
	ConstructTransferTxInfo: construct generic transfer tx, sign txInfo
*/
func ConstructTransferTxInfo(sk *PrivateKey, segmentStr string) (txInfo *TransferTxInfo, err error) {
	var segmentFormat *TransferSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructTransferTxInfo] err info:", err)
		return nil, err
	}
	assetAmount, err := StringToBigInt(segmentFormat.AssetAmount)
	if err != nil {
		log.Println("[ConstructTransferTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetAmount, _ = CleanPackedAmount(assetAmount)
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructTransferTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	txInfo = &TransferTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		ToAccountIndex:    segmentFormat.ToAccountIndex,
		ToAccountNameHash: segmentFormat.ToAccountNameHash,
		AssetId:           segmentFormat.AssetId,
		AssetAmount:       assetAmount,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		Memo:              segmentFormat.Memo,
		CallData:          segmentFormat.CallData,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	hFunc.Write([]byte(txInfo.CallData))
	callDataHash := hFunc.Sum(nil)
	txInfo.CallDataHash = callDataHash
	hFunc.Reset()
	// compute msg hash
	msgHash, err := ComputeTransferMsgHash(txInfo, hFunc)
	if err != nil {
		log.Println("[ConstructTransferTxInfo] unable to compute hash:", err.Error())
		return nil, err
	}
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructTransferTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type TransferTxInfo struct {
	FromAccountIndex  int64
	ToAccountIndex    int64
	ToAccountNameHash string
	AssetId           int64
	AssetAmount       *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	Memo              string
	CallData          string
	CallDataHash      []byte
	ExpiredAt         int64
	Nonce             int64
	Sig               []byte
}

func ComputeTransferMsgHash(txInfo *TransferTxInfo, hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedAmount, err := ToPackedAmount(txInfo.AssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount", err.Error())
		return nil, err
	}
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount", err.Error())
		return nil, err
	}
	WriteInt64IntoBuf(&buf, txInfo.FromAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.ToAccountIndex)
	buf.Write(ffmath.Mod(new(big.Int).SetBytes(common.FromHex(txInfo.ToAccountNameHash)), curve.Modulus).FillBytes(make([]byte, 32)))
	WriteInt64IntoBuf(&buf, txInfo.AssetId)
	WriteInt64IntoBuf(&buf, packedAmount)
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteInt64IntoBuf(&buf, int64(packedFee))
	buf.Write(ffmath.Mod(new(big.Int).SetBytes(txInfo.CallDataHash), curve.Modulus).FillBytes(make([]byte, 32)))
	WriteInt64IntoBuf(&buf, txInfo.ExpiredAt)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	WriteInt64IntoBuf(&buf, ChainId)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash, nil
}
