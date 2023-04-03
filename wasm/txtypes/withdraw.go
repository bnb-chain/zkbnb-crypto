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

type WithdrawSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	AssetId           int64  `json:"asset_id"`
	AssetAmount       string `json:"asset_amount"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	ToAddress         string `json:"to_address"`
	ExpiredAt         int64  `json:"expired_at"`
	Nonce             int64  `json:"nonce"`
}

func ConstructWithdrawTxInfo(sk *PrivateKey, segmentStr string) (txInfo *WithdrawTxInfo, err error) {
	var segmentFormat *WithdrawSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructWithdrawTxInfo] err info:", err)
		return nil, err
	}
	assetAmount, err := StringToBigInt(segmentFormat.AssetAmount)
	if err != nil {
		log.Println("[ConstructWithdrawTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetAmount, _ = CleanPackedAmount(assetAmount)
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructWithdrawTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	txInfo = &WithdrawTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		AssetId:           segmentFormat.AssetId,
		AssetAmount:       assetAmount,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		ToAddress:         segmentFormat.ToAddress,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		log.Println("[ConstructWithdrawTxInfo] unable to compute hash:", err)
		return nil, err
	}
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructWithdrawTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type WithdrawTxInfo struct {
	FromAccountIndex  int64
	AssetId           int64
	AssetAmount       *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	ToAddress         string
	ExpiredAt         int64
	Nonce             int64
	Sig               []byte
	L1Sig             string
}

func (txInfo *WithdrawTxInfo) Validate() error {
	if txInfo.FromAccountIndex < minAccountIndex {
		return ErrFromAccountIndexTooLow
	}
	if txInfo.FromAccountIndex > maxAccountIndex {
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
	if txInfo.AssetAmount.Cmp(minAssetAmount) <= 0 {
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

	// ToAddress
	if !IsValidL1Address(txInfo.ToAddress) {
		return ErrToAddressInvalid
	}
	return nil
}

func (txInfo *WithdrawTxInfo) VerifySignature(pubKey string) error {
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

func (txInfo *WithdrawTxInfo) GetTxType() int {
	return TxTypeWithdraw
}

func (txInfo *WithdrawTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *WithdrawTxInfo) GetAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *WithdrawTxInfo) GetFromAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *WithdrawTxInfo) GetToAccountIndex() int64 {
	return NilAccountIndex
}

func (txInfo *WithdrawTxInfo) GetL1SignatureBody() string {
	signatureBody := fmt.Sprintf(signature.SignatureTemplateWithdrawal, util.FormatWeiToEtherStr(txInfo.AssetAmount), txInfo.ToAddress,
		util.FormatWeiToEtherStr(txInfo.GasFeeAssetAmount), txInfo.GasAccountIndex, txInfo.Nonce)
	return signatureBody
}

func (txInfo *WithdrawTxInfo) GetL1AddressBySignature() common.Address {
	return signature.CalculateL1AddressBySignature(txInfo.GetL1SignatureBody(), txInfo.L1Sig)
}

func (txInfo *WithdrawTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *WithdrawTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func (txInfo *WithdrawTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount: ", err.Error())
		return nil, err
	}
	msgHash = Poseidon(ChainId, TxTypeWithdraw, txInfo.FromAccountIndex, txInfo.Nonce, txInfo.ExpiredAt, txInfo.GasFeeAssetId, packedFee,
		txInfo.AssetId, txInfo.AssetAmount, PaddingAddressToBytes20(txInfo.ToAddress))
	return msgHash, nil
}

func (txInfo *WithdrawTxInfo) GetGas() (int64, int64, *big.Int) {
	return txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount
}
