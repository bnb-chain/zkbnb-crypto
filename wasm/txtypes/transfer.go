/*
 * Copyright © 2022 ZkBNB Protocol
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

package txtypes

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bnb-chain/zkbnb-crypto/util"
	"github.com/bnb-chain/zkbnb-crypto/wasm/signature"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type TransferSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	ToL1Address       string `json:"to_l1_address"`
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
		ToL1Address:       segmentFormat.ToL1Address,
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
	msgHash, err := txInfo.Hash(hFunc)
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
	ToL1Address       string
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
	L1Sig             string
}

func (txInfo *TransferTxInfo) Validate() error {
	if txInfo.FromAccountIndex < minAccountIndex {
		return ErrFromAccountIndexTooLow
	}
	if txInfo.FromAccountIndex > maxAccountIndex {
		return ErrFromAccountIndexTooHigh
	}

	if txInfo.ToAccountIndex < minAccountIndex-1 {
		return ErrFromAccountIndexTooLow
	}
	if txInfo.ToAccountIndex > maxAccountIndex {
		return ErrFromAccountIndexTooHigh
	}

	if txInfo.AssetId < minAssetId {
		return ErrAssetIdTooLow
	}
	if txInfo.AssetId > maxAssetId {
		return ErrAssetIdTooHigh
	}

	if txInfo.AssetAmount == nil {
		return fmt.Errorf("AssetAmount should not be nil")
	}
	if txInfo.AssetAmount.Cmp(minAssetAmount) < 0 {
		return ErrAssetAmountTooLow
	}
	if txInfo.AssetAmount.Cmp(maxAssetAmount) > 0 {
		return ErrAssetAmountTooHigh
	}
	assetAmount, _ := CleanPackedAmount(txInfo.AssetAmount)
	if txInfo.AssetAmount.Cmp(assetAmount) != 0 {
		return ErrAssetAmountPrecision
	}

	if txInfo.GasAccountIndex < minAccountIndex {
		return ErrGasAccountIndexTooLow
	}
	if txInfo.GasAccountIndex > maxAccountIndex {
		return ErrGasAccountIndexTooHigh
	}

	if txInfo.GasFeeAssetId < minAssetId {
		return ErrGasFeeAssetIdTooLow
	}
	if txInfo.GasFeeAssetId > maxAssetId {
		return ErrGasFeeAssetIdTooHigh
	}

	if txInfo.GasFeeAssetAmount == nil {
		return fmt.Errorf("GasFeeAssetAmount should not be nil")
	}
	if txInfo.GasFeeAssetAmount.Cmp(minPackedFeeAmount) < 0 {
		return ErrGasFeeAssetAmountTooLow
	}
	if txInfo.GasFeeAssetAmount.Cmp(maxPackedFeeAmount) > 0 {
		return ErrGasFeeAssetAmountTooHigh
	}
	gasFeeAmount, _ := CleanPackedFee(txInfo.GasFeeAssetAmount)
	if txInfo.GasFeeAssetAmount.Cmp(gasFeeAmount) != 0 {
		return ErrGasFeeAssetAmountPrecision
	}

	if txInfo.Nonce < minNonce {
		return ErrNonceTooLow
	}

	// ToL1Address
	if !IsValidHash(txInfo.ToL1Address) {
		return ErrToL1AddressInvalid
	}

	// CallData
	if len(txInfo.CallData) > maxLength {
		return ErrCallDataInvalid
	}

	// Memo
	if len(txInfo.Memo) > maxLength {
		return ErrMemoInvalid
	}

	// CallDataHash
	if !IsValidHashBytes(txInfo.CallDataHash) {
		return ErrCallDataHashInvalid
	}
	return nil
}

func (txInfo *TransferTxInfo) VerifySignature(pubKey string) error {
	// compute hash
	hFunc := mimc.NewMiMC()
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		return err
	}
	// verify signature
	hFunc.Reset()
	pk, err := ParsePublicKey(pubKey)
	if err != nil {
		return err
	}
	isValid, err := pk.Verify(txInfo.Sig, msgHash, hFunc)
	if err != nil {
		return err
	}

	if !isValid {
		return errors.New("invalid signature")
	}
	return nil
}

func (txInfo *TransferTxInfo) GetTxType() int {
	return TxTypeTransfer
}

func (txInfo *TransferTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *TransferTxInfo) GetAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *TransferTxInfo) GetFromAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *TransferTxInfo) GetToAccountIndex() int64 {
	return txInfo.ToAccountIndex
}

func (txInfo *TransferTxInfo) GetL1SignatureBody() string {
	signatureBody := fmt.Sprintf(signature.SignatureTemplateTransfer, util.FormatWeiToEtherStr(txInfo.AssetAmount), txInfo.FromAccountIndex,
		txInfo.ToL1Address, util.FormatWeiToEtherStr(txInfo.GasFeeAssetAmount), txInfo.GasAccountIndex, txInfo.Nonce)
	return signatureBody
}

func (txInfo *TransferTxInfo) GetL1AddressBySignature() common.Address {
	return signature.CalculateL1AddressBySignature(txInfo.GetL1SignatureBody(), txInfo.L1Sig)
}

func (txInfo *TransferTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *TransferTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func (txInfo *TransferTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
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
	msgHash = Poseidon(ChainId, TxTypeTransfer, txInfo.FromAccountIndex, txInfo.Nonce, txInfo.ExpiredAt,
		txInfo.GasFeeAssetId, packedFee, txInfo.AssetId, packedAmount,
		PaddingAddressToBytes20(txInfo.ToL1Address), txInfo.CallDataHash)
	return msgHash, nil
}

func (txInfo *TransferTxInfo) GetGas() (int64, int64, *big.Int) {
	return txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount
}
