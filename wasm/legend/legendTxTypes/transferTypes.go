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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/encode/abi"
	abiEth "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
	"hash"
	"log"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ethereum/go-ethereum/common"

	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
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

func (txInfo *TransferTxInfo) Validate() error {
	if txInfo.FromAccountIndex < minAccountIndex {
		return fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.FromAccountIndex > maxAccountIndex {
		return fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex)
	}

	if txInfo.ToAccountIndex < minAccountIndex {
		return fmt.Errorf("ToAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.ToAccountIndex > maxAccountIndex {
		return fmt.Errorf("ToAccountIndex should not be larger than %d", maxAccountIndex)
	}

	if txInfo.AssetId < minAssetId {
		return fmt.Errorf("AssetId should not be less than %d", minAssetId)
	}
	if txInfo.AssetId > maxAssetId {
		return fmt.Errorf("AssetId should not be larger than %d", maxAssetId)
	}

	if txInfo.AssetAmount == nil {
		return fmt.Errorf("AssetAmount should not be nil")
	}
	if txInfo.AssetAmount.Cmp(minAssetAmount) < 0 {
		return fmt.Errorf("AssetAmount should not be less than %s", minAssetAmount.String())
	}
	if txInfo.AssetAmount.Cmp(maxAssetAmount) > 0 {
		return fmt.Errorf("AssetAmount should not be larger than %s", maxAssetAmount.String())
	}

	if txInfo.GasAccountIndex < minAccountIndex {
		return fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.GasAccountIndex > maxAccountIndex {
		return fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex)
	}

	if txInfo.GasFeeAssetId < minAssetId {
		return fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId)
	}
	if txInfo.GasFeeAssetId > maxAssetId {
		return fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId)
	}

	if txInfo.GasFeeAssetAmount == nil {
		return fmt.Errorf("GasFeeAssetAmount should not be nil")
	}
	if txInfo.GasFeeAssetAmount.Cmp(minPackedFeeAmount) < 0 {
		return fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String())
	}
	if txInfo.GasFeeAssetAmount.Cmp(maxPackedFeeAmount) > 0 {
		return fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String())
	}

	if txInfo.Nonce < minNonce {
		return fmt.Errorf("Nonce should not be less than %d", minNonce)
	}

	// ToAccountNameHash
	if !IsValidHash(txInfo.ToAccountNameHash) {
		return fmt.Errorf("ToAccountNameHash(%s) is invalid", txInfo.ToAccountNameHash)
	}

	// CallDataHash
	if !IsValidHashBytes(txInfo.CallDataHash) {
		return fmt.Errorf("CallDataHash(%s) is invalid", hex.EncodeToString(txInfo.CallDataHash))
	}

	return nil
}

func (txInfo *TransferTxInfo) VerifySignature(pubKey string) error {
	// compute hash

	abiTransfer, err := abiEth.JSON(strings.NewReader(abi.TransferABIJSON))
	if err != nil {
		return err
	}
	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.Transfer)

	inner, err := abiTransfer.Pack("", messageTypeBytes32, txInfo.FromAccountIndex, txInfo.ToAccountIndex, ConvertStringHexToBytes32(txInfo.ToAccountNameHash), uint16(txInfo.AssetId), txInfo.AssetAmount, txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount, ConvertBytesToBytes32(txInfo.CallDataHash), txInfo.ExpiredAt, txInfo.Nonce, ChainId)
	if err != nil {
		return err
	}

	innerKeccak := crypto.Keccak256(inner)
	prefixBytes, err := hex.DecodeString(abi.HexPrefixAndEip712DomainKeccakHash)
	if err != nil {
		return err
	}

	outerBytes := append(prefixBytes, innerKeccak...)
	outerBytesKeccak := crypto.Keccak256(outerBytes)

	pk, err := crypto.Ecrecover(outerBytesKeccak, txInfo.Sig)
	if common.Bytes2Hex(pk) != pubKey {
		return errors.New("invalid signature")
	}
	return nil
}

func (txInfo *TransferTxInfo) GetTxType() int {
	return TxTypeTransfer
}

func (txInfo *TransferTxInfo) GetFromAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *TransferTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *TransferTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
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
