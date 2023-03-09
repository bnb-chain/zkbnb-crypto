package txtypes

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"hash"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type ChangePubKeySegmentFormat struct {
	AccountIndex      int64  `json:"account_index"`
	L1Address         string `json:"l1_address"`
	PubKey            string `json:"pub_key"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	ExpiredAt         int64  `json:"expired_at"`
	Nonce             int64  `json:"nonce"`
}

func ConstructChangePubKeyInfo(sk *PrivateKey, segmentStr string) (txInfo *ChangePubKeyInfo, err error) {
	var segmentFormat *ChangePubKeySegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructChangePubKeyInfo] err info:", err)
		return nil, err
	}
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructChangePubKeyInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	txInfo = &ChangePubKeyInfo{
		AccountIndex:      segmentFormat.AccountIndex,
		L1Address:         segmentFormat.L1Address,
		Nonce:             segmentFormat.Nonce,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Sig:               nil,
	}
	pk, err := ParsePublicKey(segmentFormat.PubKey)
	if err != nil {
		return nil, err
	}
	txInfo.PubKeyX = pk.A.X.Marshal()
	txInfo.PubKeyY = pk.A.Y.Marshal()
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		log.Println("[ConstructChangePubKeyInfo] unable to compute hash:", err)
		return nil, err
	}
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructChangePubKeyInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type ChangePubKeyInfo struct {
	AccountIndex      int64
	L1Address         string
	Nonce             int64
	PubKeyX           []byte
	PubKeyY           []byte
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	ExpiredAt         int64
	Sig               []byte
	L1Sig             string
}

func (txInfo *ChangePubKeyInfo) GetTxType() int {
	return TxTypeChangePubKey
}

func (txInfo *ChangePubKeyInfo) Validate() error {
	if txInfo.AccountIndex < minAccountIndex {
		return ErrFromAccountIndexTooLow
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return ErrFromAccountIndexTooHigh
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

	if txInfo.Nonce < minNonce {
		return ErrNonceTooLow
	}

	// PubKeyX
	if !IsValidHashBytes(txInfo.PubKeyX) {
		return ErrPubKeyXYInvalid
	}
	// PubKeyY
	if !IsValidHashBytes(txInfo.PubKeyY) {
		return ErrPubKeyXYInvalid
	}
	// L1Address
	if !IsValidHash(txInfo.L1Address) {
		return ErrToL1AddressInvalid
	}
	if len(txInfo.L1Sig) == 0 {
		return ErrL1SigInvalid
	}
	return nil
}

func (txInfo *ChangePubKeyInfo) VerifySignature(pubKey string) error {
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

func (txInfo *ChangePubKeyInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *ChangePubKeyInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *ChangePubKeyInfo) GetToAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *ChangePubKeyInfo) GetL1Signature() string {
	return ""
}

func (txInfo *ChangePubKeyInfo) GetL1AddressBySignatureInfo() (common.Address, common.Address) {
	message := accounts.TextHash([]byte(txInfo.L1Sig))
	//Decode from signature string to get the signature byte array
	signatureContent, err := hexutil.Decode(txInfo.GetL1Signature())
	if err != nil {
		return [20]byte{}, [20]byte{}
	}
	signatureContent[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	//Calculate the public key from the signature and source string
	signaturePublicKey, err := crypto.SigToPub(message, signatureContent)
	if err != nil {
		return [20]byte{}, [20]byte{}
	}

	//Calculate the address from the public key
	publicAddress := crypto.PubkeyToAddress(*signaturePublicKey)
	return publicAddress, [20]byte{}
}

func (txInfo *ChangePubKeyInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *ChangePubKeyInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func (txInfo *ChangePubKeyInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeChangePubKeyMsgHash] unable to packed amount: ", err.Error())
		return nil, err
	}
	msgHash = Poseidon(ChainId, TxTypeChangePubKey, txInfo.AccountIndex, txInfo.Nonce, txInfo.ExpiredAt, txInfo.GasFeeAssetId, packedFee,
		PaddingAddressToBytes32(txInfo.L1Address), txInfo.PubKeyX, txInfo.PubKeyY)
	return msgHash, nil
}

func (txInfo *ChangePubKeyInfo) GetGas() (int64, int64, *big.Int) {
	return txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount
}
