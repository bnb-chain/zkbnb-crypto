package txtypes

import (
	"errors"
	"fmt"
	"github.com/bnb-chain/zkbnb-crypto/wasm/signature"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"hash"
	"math/big"
)

type UpdateNFTTxInfo struct {
	NftIndex          int64
	MutableAttributes string
	AccountIndex      int64
	Nonce             int64
	L1Sig             string
}

func (txInfo *UpdateNFTTxInfo) GetTxType() int {
	return TxTypeUpdateNFT
}

func (txInfo *UpdateNFTTxInfo) Validate() error {
	return nil
}

func (txInfo *UpdateNFTTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *UpdateNFTTxInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *UpdateNFTTxInfo) GetFromAccountIndex() int64 {
	return NilAccountIndex
}

func (txInfo *UpdateNFTTxInfo) GetToAccountIndex() int64 {
	return NilAccountIndex
}

func (txInfo *UpdateNFTTxInfo) GetL1Signature() string {
	signatureBody := fmt.Sprintf(signature.SignatureTemplateUpdateNFT, txInfo.AccountIndex, txInfo.NftIndex, txInfo.Nonce)
	return signatureBody
}

func (txInfo *UpdateNFTTxInfo) GetL1AddressBySignatureInfo() common.Address {
	message := accounts.TextHash([]byte(txInfo.L1Sig))
	//Decode from signature string to get the signature byte array
	signatureContent, err := hexutil.Decode(txInfo.GetL1Signature())
	if err != nil {
		return [20]byte{}
	}
	signatureContent[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	//Calculate the public key from the signature and source string
	signaturePublicKey, err := crypto.SigToPub(message, signatureContent)
	if err != nil {
		return [20]byte{}
	}

	//Calculate the address from the public key
	publicAddress := crypto.PubkeyToAddress(*signaturePublicKey)
	return publicAddress
}

func (txInfo *UpdateNFTTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *UpdateNFTTxInfo) GetExpiredAt() int64 {
	return NilExpiredAt
}

func (txInfo *UpdateNFTTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	return msgHash, errors.New("not support")
}

func (txInfo *UpdateNFTTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilAccountIndex, NilAssetId, nil
}
