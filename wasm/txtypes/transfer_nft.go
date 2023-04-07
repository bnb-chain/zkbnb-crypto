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

type TransferNftSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	ToL1Address       string `json:"to_l1_address"`
	NftIndex          int64  `json:"nft_index"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	CallData          string `json:"call_data"`
	ExpiredAt         int64  `json:"expired_at"`
	Nonce             int64  `json:"nonce"`
}

func ConstructTransferNftTxInfo(sk *PrivateKey, segmentStr string) (txInfo *TransferNftTxInfo, err error) {
	var segmentFormat *TransferNftSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructTransferNftTxInfo] err info:", err)
		return nil, err
	}
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructTransferNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedAmount(gasFeeAmount)
	txInfo = &TransferNftTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		ToL1Address:       segmentFormat.ToL1Address,
		NftIndex:          segmentFormat.NftIndex,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute msg hash
	hFunc := mimc.NewMiMC()
	hFunc.Write([]byte(txInfo.CallData))
	callDataHash := hFunc.Sum(nil)
	txInfo.CallDataHash = callDataHash
	hFunc.Reset()
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		log.Println("[ConstructTransferNftTxInfo] unable to compute hash:", err)
		return nil, err
	}
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructTransferNftTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type TransferNftTxInfo struct {
	FromAccountIndex  int64
	ToAccountIndex    int64
	ToL1Address       string
	NftIndex          int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	CallData          string
	CallDataHash      []byte
	ExpiredAt         int64
	Nonce             int64
	Sig               []byte
	L1Sig             string
}

func (txInfo *TransferNftTxInfo) Validate() error {
	// FromAccountIndex
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

	// ToL1Address
	if !IsValidHash(txInfo.ToL1Address) {
		return ErrToL1AddressInvalid
	}

	// NftIndex
	if txInfo.NftIndex < minNftIndex {
		return ErrNftIndexTooLow
	}
	if txInfo.NftIndex > maxNftIndex {
		return ErrNftIndexTooHigh
	}

	// GasAccountIndex
	if txInfo.GasAccountIndex < minAccountIndex {
		return ErrGasAccountIndexTooLow
	}
	if txInfo.GasAccountIndex > maxAccountIndex {
		return ErrGasAccountIndexTooHigh
	}

	// GasFeeAssetId
	if txInfo.GasFeeAssetId < minAssetId {
		return ErrGasFeeAssetIdTooLow
	}
	if txInfo.GasFeeAssetId > maxAssetId {
		return ErrGasFeeAssetIdTooHigh
	}

	// GasFeeAssetAmount
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

	// CallData
	if len(txInfo.CallData) > maxLength {
		return ErrCallDataInvalid
	}

	// CallDataHash
	if !IsValidHashBytes(txInfo.CallDataHash) {
		return ErrCallDataHashInvalid
	}

	// Nonce
	if txInfo.Nonce < minNonce {
		return ErrNonceTooLow
	}
	return nil
}

func (txInfo *TransferNftTxInfo) VerifySignature(pubKey string) error {
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

func (txInfo *TransferNftTxInfo) GetTxType() int {
	return TxTypeTransferNft
}

func (txInfo *TransferNftTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *TransferNftTxInfo) GetAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *TransferNftTxInfo) GetFromAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *TransferNftTxInfo) GetToAccountIndex() int64 {
	return txInfo.ToAccountIndex
}

func (txInfo *TransferNftTxInfo) GetL1SignatureBody() string {
	signatureBody := fmt.Sprintf(signature.SignatureTemplateTransferNft, txInfo.NftIndex, txInfo.FromAccountIndex,
		txInfo.ToL1Address, util.FormatWeiToEtherStr(txInfo.GasFeeAssetAmount), txInfo.GasAccountIndex, txInfo.Nonce)
	return signatureBody
}

func (txInfo *TransferNftTxInfo) GetL1AddressBySignature() common.Address {
	return signature.CalculateL1AddressBySignature(txInfo.GetL1SignatureBody(), txInfo.L1Sig)
}

func (txInfo *TransferNftTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *TransferNftTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func (txInfo *TransferNftTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount", err.Error())
		return nil, err
	}
	msgHash = Poseidon(ChainId, TxTypeTransferNft, txInfo.FromAccountIndex, txInfo.Nonce, txInfo.ExpiredAt,
		txInfo.GasFeeAssetId, packedFee, txInfo.NftIndex, PaddingAddressToBytes20(txInfo.ToL1Address),
		txInfo.CallDataHash)
	return msgHash, nil
}

func (txInfo *TransferNftTxInfo) GetGas() (int64, int64, *big.Int) {
	return txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount
}
