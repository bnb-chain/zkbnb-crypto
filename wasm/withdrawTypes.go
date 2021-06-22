package wasm

import (
	"encoding/json"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	WithdrawSegment: which is used to construct withdraw proof
*/
type WithdrawSegment struct {
	EncVal *ElGamalEnc `json:"enc_val"`
	Pk     *Point      `json:"pk"`
	BStar  *big.Int    `json:"b_star"`
	Sk     *big.Int    `json:"sk"`
}

/*
	WithdrawSegmentFormat: format version of WithdrawSegment
*/
type WithdrawSegmentFormat struct {
	EncVal string `json:"enc_val"`
	Pk     string `json:"pk"`
	BStar  int    `json:"b_star"`
	Sk     string `json:"sk"`
}

func FromWithdrawSegmentJSON(segmentStr string) (*WithdrawSegment, int) {
	var withdrawSegmentFormat *WithdrawSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &withdrawSegmentFormat)
	if err != nil {
		return nil, ErrUnmarshal
	}
	if withdrawSegmentFormat.EncVal == "" || withdrawSegmentFormat.Pk == "" ||
		withdrawSegmentFormat.BStar <= 0 || withdrawSegmentFormat.Sk == "" {
		return nil, ErrInvalidWithdrawParams
	}
	encVal, err := twistedElgamal.FromString(withdrawSegmentFormat.EncVal)
	if err != nil {
		return nil, ErrParseEnc
	}
	pk, err := curve.FromString(withdrawSegmentFormat.Pk)
	if err != nil {
		return nil, ErrParsePoint
	}
	bStar := big.NewInt(int64(withdrawSegmentFormat.BStar))
	sk, b := new(big.Int).SetString(withdrawSegmentFormat.Sk, 10)
	if !b {
		return nil, ErrParseBigInt
	}
	withdrawSegment := &WithdrawSegment{
		EncVal: encVal,
		Pk:     pk,
		BStar:  bStar,
		Sk:     sk,
	}
	return withdrawSegment, Success
}

type WithdrawTransactionAo struct {
	// token id
	TokenId uint32
	// account index
	AccountId int
	// withdraw proof
	Proof *zecrey.WithdrawProof
	// create time
	CreateAt int64
}
