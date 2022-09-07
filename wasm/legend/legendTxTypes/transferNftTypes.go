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

type TransferNftSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	ToAccountIndex    int64  `json:"to_account_index"`
	ToAccountNameHash string `json:"to_account_name"`
	NftIndex          int64  `json:"nft_index"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	CallData          string `json:"call_data"`
	ExpiredAt         int64  `json:"expired_at"`
	Nonce             int64  `json:"nonce"`
}

/*
	ConstructTransferNftTxInfo: construct transfer nft tx, sign txInfo
*/
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
		ToAccountIndex:    segmentFormat.ToAccountIndex,
		ToAccountNameHash: segmentFormat.ToAccountNameHash,
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
	msgHash, err := ComputeTransferNftMsgHash(txInfo, hFunc)
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
	ToAccountNameHash string
	NftIndex          int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	CallData          string
	CallDataHash      []byte
	ExpiredAt         int64
	Nonce             int64
	Sig               []byte
}

func (txInfo *TransferNftTxInfo) Validate() error {
	// FromAccountIndex
	if txInfo.FromAccountIndex < minAccountIndex {
		return fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.FromAccountIndex > maxAccountIndex {
		return fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex)
	}

	// ToAccountIndex
	if txInfo.ToAccountIndex < minAccountIndex {
		return fmt.Errorf("ToAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.ToAccountIndex > maxAccountIndex {
		return fmt.Errorf("ToAccountIndex should not be larger than %d", maxAccountIndex)
	}

	// ToAccountNameHash
	if !IsValidHash(txInfo.ToAccountNameHash) {
		return fmt.Errorf("ToAccountNameHash(%s) is invalid", txInfo.ToAccountNameHash)
	}

	// NftIndex
	if txInfo.NftIndex < minNftIndex {
		return fmt.Errorf("NftIndex should not be less than %d", minNftIndex)
	}
	if txInfo.NftIndex > maxNftIndex {
		return fmt.Errorf("NftIndex should not be larger than %d", maxNftIndex)
	}

	// GasAccountIndex
	if txInfo.GasAccountIndex < minAccountIndex {
		return fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.GasAccountIndex > maxAccountIndex {
		return fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex)
	}

	// GasFeeAssetId
	if txInfo.GasFeeAssetId < minAssetId {
		return fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId)
	}
	if txInfo.GasFeeAssetId > maxAssetId {
		return fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId)
	}

	// GasFeeAssetAmount
	if txInfo.GasFeeAssetAmount == nil {
		return fmt.Errorf("GasFeeAssetAmount should not be nil")
	}
	if txInfo.GasFeeAssetAmount.Cmp(minPackedFeeAmount) < 0 {
		return fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String())
	}
	if txInfo.GasFeeAssetAmount.Cmp(maxPackedFeeAmount) > 0 {
		return fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String())
	}

	// CallDataHash
	if !IsValidHashBytes(txInfo.CallDataHash) {
		return fmt.Errorf("CallDataHash(%s) is invalid", hex.EncodeToString(txInfo.CallDataHash))
	}

	// Nonce
	if txInfo.Nonce < minNonce {
		return fmt.Errorf("Nonce should not be less than %d", minNonce)
	}

	return nil
}

func (txInfo *TransferNftTxInfo) VerifySignature(pubKey string) error {
	// compute hash

	abiEncoder, err := abiEth.JSON(strings.NewReader(abi.TransferNftABIJSON))
	if err != nil {
		return err
	}
	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.Transfer)

	inner, err := abiEncoder.Pack("", messageTypeBytes32, txInfo.FromAccountIndex, txInfo.ToAccountIndex, ConvertStringHexToBytes32(txInfo.ToAccountNameHash), txInfo.NftIndex, txInfo.CallDataHash, txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount, ConvertBytesToBytes32(txInfo.CallDataHash), txInfo.ExpiredAt, txInfo.Nonce, ChainId)
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

func (txInfo *TransferNftTxInfo) GetTxType() int {
	return TxTypeTransferNft
}

func (txInfo *TransferNftTxInfo) GetFromAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *TransferNftTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *TransferNftTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func ComputeTransferNftMsgHash(txInfo *TransferNftTxInfo, hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount", err.Error())
		return nil, err
	}
	WriteInt64IntoBuf(&buf, txInfo.FromAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.ToAccountIndex)
	buf.Write(ffmath.Mod(new(big.Int).SetBytes(common.FromHex(txInfo.ToAccountNameHash)), curve.Modulus).FillBytes(make([]byte, 32)))
	WriteInt64IntoBuf(&buf, txInfo.NftIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteInt64IntoBuf(&buf, packedFee)
	buf.Write(ffmath.Mod(new(big.Int).SetBytes(txInfo.CallDataHash), curve.Modulus).FillBytes(make([]byte, 32)))
	WriteInt64IntoBuf(&buf, txInfo.ExpiredAt)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	WriteInt64IntoBuf(&buf, ChainId)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash, nil
}
