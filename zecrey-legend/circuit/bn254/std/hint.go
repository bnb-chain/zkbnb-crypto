package std

import (
	"bytes"
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"log"
	"math/big"
)

func Keccak256(curveID ecc.ID, inputs []*big.Int, outputs []*big.Int) error {
	var buf bytes.Buffer
	for i := 0; i < len(inputs); i++ {
		buf.Write(inputs[i].FillBytes(make([]byte, 32)))
	}
	hashVal := crypto.Keccak256Hash(buf.Bytes())
	result := outputs[0]
	result.SetBytes(hashVal[:])
	return nil
}

var (
	PackedAmountMaxAmount   = ffmath.Multiply(big.NewInt(34359738367), new(big.Int).Exp(big.NewInt(10), big.NewInt(31), nil))
	PackedAmountMaxMantissa = big.NewInt(34359738367)
	ZeroBigInt              = big.NewInt(0)
)

func CleanPackedAmount(amount *big.Int) (nAmount *big.Int, err error) {
	if amount.Cmp(ZeroBigInt) < 0 || amount.Cmp(PackedAmountMaxAmount) > 0 {
		log.Println("[ToPackedAmount] invalid amount")
		return nil, errors.New("[ToPackedAmount] invalid amount")
	}
	oAmount := new(big.Int).Set(amount)
	exponent := int64(0)
	for oAmount.Cmp(PackedAmountMaxMantissa) > 0 {
		oAmount = ffmath.Div(oAmount, big.NewInt(10))
		exponent++
	}
	nAmount = ffmath.Multiply(oAmount, new(big.Int).Exp(big.NewInt(10), big.NewInt(exponent), nil))
	return nAmount, nil
}

func ComputeSLp(curveID ecc.ID, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 5 {
		return errors.New("[ComputeSLp] invalid params")
	}
	poolA := inputs[0]
	poolB := inputs[1]
	kLast := inputs[2]
	feeRate := inputs[3]
	treasuryRate := inputs[4]
	if poolA.Cmp(ZeroBigInt) == 0 || poolB.Cmp(ZeroBigInt) == 0 {
		outputs[0] = ZeroBigInt
		return nil
	}
	kCurrent := ffmath.Multiply(poolA, poolB)
	kLast.Sqrt(kLast)
	kCurrent.Sqrt(kCurrent)
	l := ffmath.Multiply(ffmath.Sub(kCurrent, kLast), big.NewInt(RateBase))
	r := ffmath.Multiply(ffmath.Sub(ffmath.Multiply(big.NewInt(RateBase), ffmath.Div(feeRate, treasuryRate)), big.NewInt(RateBase)), kCurrent)
	r = ffmath.Add(r, ffmath.Multiply(big.NewInt(RateBase), kLast))
	var err error
	outputs[0], err = CleanPackedAmount(ffmath.Div(l, r))
	if err != nil {
		return err
	}
	return nil
}
