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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"hash"
	"log"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type AddLiquiditySegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	PairIndex         int64  `json:"pair_index"`
	AssetAId          int64  `json:"asset_a_id"`
	AssetAAmount      string `json:"asset_a_amount"`
	AssetBId          int64  `json:"asset_b_id"`
	AssetBAmount      string `json:"asset_b_amount"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	ExpiredAt         int64  `json:"expired_at"`
	Nonce             int64  `json:"nonce"`
}

func ConstructAddLiquidityTxInfo(sk *PrivateKey, segmentStr string) (txInfo *AddLiquidityTxInfo, err error) {
	var segmentFormat *AddLiquiditySegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] err info:", err)
		return nil, err
	}
	// TODO lp amount
	assetAAmount, err := StringToBigInt(segmentFormat.AssetAAmount)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetAAmount, _ = CleanPackedAmount(assetAAmount)
	assetBAmount, err := StringToBigInt(segmentFormat.AssetBAmount)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetBAmount, _ = CleanPackedAmount(assetBAmount)
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	txInfo = &AddLiquidityTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		PairIndex:         segmentFormat.PairIndex,
		AssetAId:          segmentFormat.AssetAId,
		AssetAAmount:      assetAAmount,
		AssetBId:          segmentFormat.AssetBId,
		AssetBAmount:      assetBAmount,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := ComputeAddLiquidityMsgHash(txInfo, hFunc)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to compute hash:", err)
		return nil, err
	}
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type AddLiquidityTxInfo struct {
	FromAccountIndex  int64
	PairIndex         int64
	AssetAId          int64
	AssetAAmount      *big.Int
	AssetBId          int64
	AssetBAmount      *big.Int
	LpAmount          *big.Int
	KLast             *big.Int
	TreasuryAmount    *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	ExpiredAt         int64
	Nonce             int64
	Sig               []byte
}

func (txInfo *AddLiquidityTxInfo) Validate() error {
	if txInfo.FromAccountIndex < minAccountIndex {
		return fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.FromAccountIndex > maxAccountIndex {
		return fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex)
	}

	if txInfo.PairIndex < minPairIndex {
		return fmt.Errorf("PairIndex should not be less than %d", minPairIndex)
	}
	if txInfo.PairIndex > maxPairIndex {
		return fmt.Errorf("PairIndex should not be larger than %d", maxPairIndex)
	}

	if txInfo.AssetAAmount == nil {
		return fmt.Errorf("AssetAAmount should not be nil")
	}
	if txInfo.AssetAAmount.Cmp(minAssetAmount) < 0 {
		return fmt.Errorf("AssetAAmount should not be less than %s", minAssetAmount.String())
	}
	if txInfo.AssetAAmount.Cmp(maxAssetAmount) > 0 {
		return fmt.Errorf("AssetAAmount should not be larger than %s", maxAssetAmount.String())
	}

	if txInfo.AssetBAmount == nil {
		return fmt.Errorf("AssetBAmount should not be nil")
	}
	if txInfo.AssetBAmount.Cmp(minAssetAmount) < 0 {
		return fmt.Errorf("AssetBAmount should not be less than %s", minAssetAmount.String())
	}
	if txInfo.AssetBAmount.Cmp(maxAssetAmount) > 0 {
		return fmt.Errorf("AssetBAmount should not be larger than %s", maxAssetAmount.String())
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
	return nil
}

func (txInfo *AddLiquidityTxInfo) VerifySignature(pubKey string) error {
	// compute hash

	abiEncoder, err := abiEth.JSON(strings.NewReader(abi.AddLiquidityABIJSON))
	if err != nil {
		return err
	}
	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.AddLiquidity)

	inner, err := abiEncoder.Pack("", messageTypeBytes32, txInfo.FromAccountIndex, txInfo.PairIndex, txInfo.AssetAAmount, txInfo.AssetBAmount, txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount, txInfo.ExpiredAt, txInfo.Nonce, ChainId)
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

func (txInfo *AddLiquidityTxInfo) GetTxType() int {
	return TxTypeAddLiquidity
}

func (txInfo *AddLiquidityTxInfo) GetFromAccountIndex() int64 {
	return txInfo.FromAccountIndex
}

func (txInfo *AddLiquidityTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *AddLiquidityTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func ComputeAddLiquidityMsgHash(txInfo *AddLiquidityTxInfo, hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedAAmount, err := ToPackedAmount(txInfo.AssetAAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	packedBAmount, err := ToPackedAmount(txInfo.AssetBAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	WriteInt64IntoBuf(&buf, txInfo.FromAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.PairIndex)
	WriteInt64IntoBuf(&buf, packedAAmount)
	WriteInt64IntoBuf(&buf, packedBAmount)
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteInt64IntoBuf(&buf, packedFee)
	WriteInt64IntoBuf(&buf, txInfo.ExpiredAt)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	WriteInt64IntoBuf(&buf, ChainId)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash, nil
}
