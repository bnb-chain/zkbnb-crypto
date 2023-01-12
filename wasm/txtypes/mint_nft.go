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
	curve "github.com/bnb-chain/zkbnb-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbnb-crypto/ffmath"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
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
	msgHash, err := txInfo.Hash(hFunc)
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
	MetaData            *NftMetaData
	IpnsName            string
	IpnsId              string
}

type NftMetaData struct {
	Image       string
	Name        string
	Description string
	Attributes  string
}

func (txInfo *MintNftTxInfo) Validate() error {
	// CreatorAccountIndex
	if txInfo.CreatorAccountIndex < minAccountIndex {
		return ErrCreatorAccountIndexTooLow
	}
	if txInfo.CreatorAccountIndex > maxAccountIndex {
		return ErrCreatorAccountIndexTooHigh
	}

	// ToAccountIndex
	if txInfo.ToAccountIndex < minAccountIndex {
		return ErrToAccountIndexTooLow
	}
	if txInfo.ToAccountIndex > maxAccountIndex {
		return ErrToAccountIndexTooHigh
	}

	// ToAccountNameHash
	if !IsValidHash(txInfo.ToAccountNameHash) {
		return ErrToAccountNameHashInvalid
	}

	// NftContentHash
	//if !IsValidHash(txInfo.NftContentHash) {
	//	return ErrNftContentHashInvalid
	//}

	// NftCollectionId
	if txInfo.NftCollectionId < minCollectionId {
		return ErrNftCollectionIdTooLow
	}
	if txInfo.NftCollectionId > maxCollectionId {
		return ErrNftCollectionIdTooHigh
	}

	// CreatorTreasuryRate
	if txInfo.CreatorTreasuryRate < minTreasuryRate {
		return ErrCreatorTreasuryRateTooLow
	}
	if txInfo.CreatorTreasuryRate > maxTreasuryRate {
		return ErrCreatorTreasuryRateTooHigh
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

	// Nonce
	if txInfo.Nonce < minNonce {
		return ErrNonceTooLow
	}

	return nil
}

func (txInfo *MintNftTxInfo) VerifySignature(pubKey string) error {
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

func (txInfo *MintNftTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount", err.Error())
		return nil, err
	}
	msgHash = Poseidon(ChainId, TxTypeMintNft, txInfo.CreatorAccountIndex, txInfo.Nonce, txInfo.ExpiredAt,
		txInfo.GasFeeAssetId, packedFee, txInfo.ToAccountIndex, txInfo.CreatorTreasuryRate, txInfo.NftCollectionId,
		ffmath.Mod(new(big.Int).SetBytes(common.FromHex(txInfo.ToAccountNameHash)), curve.Modulus))
	return msgHash, nil
}

func (txInfo *MintNftTxInfo) GetGas() (int64, int64, *big.Int) {
	return txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount
}
