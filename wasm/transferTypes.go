package wasm

import (
	"encoding/json"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type PTransferSegment struct {
	// ElGamalEnc
	EncVal *ElGamalEnc `json:"enc_val"`
	// public key
	Pk *Point `json:"pk"`
	// bDelta
	BDelta *big.Int `json:"b_delta"`
	// secret key
	Sk *big.Int `json:"sk"`
}

// PTransferSegmentFormat Format is used to accept JSON string
type PTransferSegmentFormat struct {
	// ElGamalEnc
	EncVal string `json:"enc_val"`
	// public key
	Pk string `json:"pk"`
	// bDelta
	BDelta int `json:"b_delta"`
	// secret key
	Sk string `json:"sk"`
}

func FromPTransferSegmentJSON(segmentStr string) ([]*PTransferSegment, int) {
	var transferSegmentFormats []*PTransferSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &transferSegmentFormats)
	if err != nil {
		return nil, ErrUnmarshal
	}
	if len(transferSegmentFormats) < 2 {
		return nil, ErrInvalidTransferParams
	}
	skCount := 0
	var segments []*PTransferSegment
	for _, segmentFormat := range transferSegmentFormats {
		if segmentFormat.EncVal == "" || segmentFormat.Pk == "" {
			return nil, ErrInvalidTransferParams
		}
		// create a new segment
		segment := new(PTransferSegment)
		// get ElGamalEnc
		encVal, err := twistedElgamal.FromString(segmentFormat.EncVal)
		if err != nil {
			return nil, ErrParseEnc
		}
		// get pk
		pk, err := curve.FromString(segmentFormat.Pk)
		if err != nil {
			return nil, ErrParsePoint
		}
		// get bDelta
		bDelta := big.NewInt(int64(segmentFormat.BDelta))
		// set values into segment
		segment.EncVal = encVal
		segment.Pk = pk
		segment.BDelta = bDelta
		// check if exists sk
		if segmentFormat.Sk != "" {
			// get sk
			skCount++
			sk, b := new(big.Int).SetString(segmentFormat.Sk, 10)
			if !b {
				return nil, ErrParseBigInt
			}
			segment.Sk = sk
		}
		segments = append(segments, segment)
	}
	if skCount != 1 {
		return nil, ErrInvalidTransferParams
	}
	return segments, Success
}

type TransferTransactionAo struct {
	// token id
	TokenId uint32
	// account indexes
	AccountIds []int
	// transfer proof
	Proof *zecrey.PTransferProof
	// create time
	CreateAt int64
}
