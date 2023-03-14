package txtypes

import (
	"errors"
	"fmt"
	"github.com/bnb-chain/zkbnb-crypto/wasm/signature"
	"github.com/ethereum/go-ethereum/common"
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

func (txInfo *UpdateNFTTxInfo) GetPubKey() string {
	return ""
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

func (txInfo *UpdateNFTTxInfo) GetL1SignatureBody() string {
	signatureBody := fmt.Sprintf(signature.SignatureTemplateUpdateNFT, txInfo.AccountIndex, txInfo.NftIndex, txInfo.Nonce)
	return signatureBody
}

func (txInfo *UpdateNFTTxInfo) GetL1AddressBySignature() common.Address {
	return signature.CalculateL1AddressBySignature(txInfo.GetL1SignatureBody(), txInfo.L1Sig)
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
