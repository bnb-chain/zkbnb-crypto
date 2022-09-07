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

type MintNftSegmentFormat struct {
	CreatorAccountIndex int64  `json:"creator_account_index"`
	ToAccountIndex      int64  `json:"to_account_index"`
	ToAccountNameHash   string `json:"to_account_name_hash"`
	NftContentHash      string `json:"nft_content_hash"`
	NftCollectionId     int64  `json:"nft_collection_id"`
	CreatorTreasuryRate int64  `json:"creator_treasury_rate"`
	GasAccountIndex     int64  `json:"gas_account_index"`
	GasFeeAssetId       int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount   string `json:"gas_fee_asset_amount"`
	ExpiredAt           int64  `json:"expired_at"`
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
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	txInfo = &MintNftTxInfo{
		CreatorAccountIndex: segmentFormat.CreatorAccountIndex,
		ToAccountIndex:      segmentFormat.ToAccountIndex,
		ToAccountNameHash:   segmentFormat.ToAccountNameHash,
		NftContentHash:      segmentFormat.NftContentHash,
		NftCollectionId:     segmentFormat.NftCollectionId,
		CreatorTreasuryRate: segmentFormat.CreatorTreasuryRate,
		GasAccountIndex:     segmentFormat.GasAccountIndex,
		GasFeeAssetId:       segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount:   gasFeeAmount,
		Nonce:               segmentFormat.Nonce,
		ExpiredAt:           segmentFormat.ExpiredAt,
		Sig:                 nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := ComputeMintNftMsgHash(txInfo, hFunc)
	if err != nil {
		log.Println("[ConstructMintNftTxInfo] unable to compute hash:", err)
		return nil, err
	}
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
	ToAccountNameHash   string
	NftIndex            int64
	NftContentHash      string
	NftCollectionId     int64
	CreatorTreasuryRate int64
	GasAccountIndex     int64
	GasFeeAssetId       int64
	GasFeeAssetAmount   *big.Int
	ExpiredAt           int64
	Nonce               int64
	Sig                 []byte
}

func (txInfo *MintNftTxInfo) Validate() error {
	// CreatorAccountIndex
	if txInfo.CreatorAccountIndex < minAccountIndex {
		return fmt.Errorf("CreatorAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.CreatorAccountIndex > maxAccountIndex {
		return fmt.Errorf("CreatorAccountIndex should not be larger than %d", maxAccountIndex)
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

	// NftContentHash
	if !IsValidHash(txInfo.NftContentHash) {
		return fmt.Errorf("NftContentHash(%s) is invalid", txInfo.NftContentHash)
	}

	// NftCollectionId
	if txInfo.NftCollectionId < minCollectionId {
		return fmt.Errorf("NftCollectionId should not be less than %d", minCollectionId)
	}
	if txInfo.NftCollectionId > maxCollectionId {
		return fmt.Errorf("NftCollectionId should not be larger than %d", maxCollectionId)
	}

	// CreatorTreasuryRate
	if txInfo.CreatorTreasuryRate < minTreasuryRate {
		return fmt.Errorf("CreatorTreasuryRate should  not be less than %d", minTreasuryRate)
	}
	if txInfo.CreatorTreasuryRate > maxTreasuryRate {
		return fmt.Errorf("CreatorTreasuryRate should not be larger than %d", maxTreasuryRate)
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

	// Nonce
	if txInfo.Nonce < minNonce {
		return fmt.Errorf("Nonce should not be less than %d", minNonce)
	}

	return nil
}

func (txInfo *MintNftTxInfo) VerifySignature(pubKey string) error {
	// compute hash

	abiEncoder, err := abiEth.JSON(strings.NewReader(abi.MintNftABIJSON))
	if err != nil {
		return err
	}
	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.MintNft)

	inner, err := abiEncoder.Pack("", messageTypeBytes32, txInfo.CreatorAccountIndex, txInfo.ToAccountIndex, ConvertStringHexToBytes32(txInfo.ToAccountNameHash), ConvertStringHexToBytes32(txInfo.NftContentHash), txInfo.NftCollectionId, txInfo.CreatorTreasuryRate, txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount, txInfo.ExpiredAt, txInfo.Nonce, ChainId)
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

func (txInfo *MintNftTxInfo) GetTxType() int {
	return TxTypeMintNft
}

func (txInfo *MintNftTxInfo) GetFromAccountIndex() int64 {
	return txInfo.CreatorAccountIndex
}

func (txInfo *MintNftTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *MintNftTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func ComputeMintNftMsgHash(txInfo *MintNftTxInfo, hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount", err.Error())
		return nil, err
	}
	WriteInt64IntoBuf(&buf, txInfo.CreatorAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.ToAccountIndex)
	WriteBigIntIntoBuf(&buf, ffmath.Mod(new(big.Int).SetBytes(common.FromHex(txInfo.ToAccountNameHash)), curve.Modulus))
	WriteBigIntIntoBuf(&buf, ffmath.Mod(new(big.Int).SetBytes(common.FromHex(txInfo.NftContentHash)), curve.Modulus))
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteInt64IntoBuf(&buf, packedFee)
	WriteInt64IntoBuf(&buf, txInfo.CreatorTreasuryRate)
	WriteInt64IntoBuf(&buf, txInfo.NftCollectionId)
	WriteInt64IntoBuf(&buf, txInfo.ExpiredAt)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	WriteInt64IntoBuf(&buf, ChainId)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash, nil
}
