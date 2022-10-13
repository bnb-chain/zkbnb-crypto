package abi

import (
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/accounts/abi"
)

type AbiEncoder interface {
	Pack(api frontend.API, name frontend.Variable, args ...frontend.Variable) ([]frontend.Variable, error)
}

type pureHintAbiEncoder struct {
	abi.ABI
}

type pureAbiEncoder struct {
	pureHintAbiEncoder
	context Context
}

// register encoder hint functions once
var encoder *pureHintAbiEncoder = nil

func NewPureAbiEncoder(context Context) (AbiEncoder, error) {
	a, err := abi.JSON(strings.NewReader(GeneralABIJSON))
	if err != nil {
		return nil, err
	}
	if encoder == nil {
		encoder = &pureHintAbiEncoder{a}
		hint.Register(encoder.HintDefaultAbi)
		hint.Register(encoder.HintTransferAbi)
		hint.Register(encoder.HintWithdrawAbi)
		hint.Register(encoder.HintCreateCollectionAbi)
		hint.Register(encoder.HintWithdrawNftAbi)
		hint.Register(encoder.HintTransferNftAbi)
		hint.Register(encoder.HintMintNftAbi)
		hint.Register(encoder.HintCancelOfferAbi)
		hint.Register(encoder.HintAtomicMatchAbi)
	}
	return &pureAbiEncoder{*encoder, context}, nil
}

func (e *pureAbiEncoder) Pack(api frontend.API, name frontend.Variable, args ...frontend.Variable) ([]frontend.Variable, error) {
	inputs := make([]frontend.Variable, 0)
	inputs = append(inputs, args...)
	defaultAbiBytes, err := api.Compiler().NewHint(e.HintDefaultAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	transferAbiBytes, err := api.Compiler().NewHint(e.HintTransferAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	withdrawAbiBytes, err := api.Compiler().NewHint(e.HintWithdrawAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	createCollectionAbiBytes, err := api.Compiler().NewHint(e.HintCreateCollectionAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	withdrawNftAbiBytes, err := api.Compiler().NewHint(e.HintWithdrawNftAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	transferNftAbiBytes, err := api.Compiler().NewHint(e.HintTransferNftAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	mintNftAbiBytes, err := api.Compiler().NewHint(e.HintMintNftAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	cancelOfferAbiBytes, err := api.Compiler().NewHint(e.HintCancelOfferAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	atomicMatchAbiBytes, err := api.Compiler().NewHint(e.HintAtomicMatchAbi, StaticArgsOutput, inputs...)
	if err != nil {
		return nil, err
	}
	var shouldSelectBytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < StaticArgsOutput; i++ {
		shouldSelectBytes[i] = 0
		shouldSelectBytes[i] = api.Select(e.context.flags.defaultApiFlag, defaultAbiBytes[i], shouldSelectBytes[i])
		shouldSelectBytes[i] = api.Select(e.context.flags.transferApiFlag, transferAbiBytes[i], shouldSelectBytes[i])
		shouldSelectBytes[i] = api.Select(e.context.flags.withdrawApiFlag, withdrawAbiBytes[i], shouldSelectBytes[i])
		shouldSelectBytes[i] = api.Select(e.context.flags.createCollectionApiFlag, createCollectionAbiBytes[i], shouldSelectBytes[i])
		shouldSelectBytes[i] = api.Select(e.context.flags.withdrawNftApiFlag, withdrawNftAbiBytes[i], shouldSelectBytes[i])
		shouldSelectBytes[i] = api.Select(e.context.flags.transferNftApiFlag, transferNftAbiBytes[i], shouldSelectBytes[i])
		shouldSelectBytes[i] = api.Select(e.context.flags.mintNftApiFlag, mintNftAbiBytes[i], shouldSelectBytes[i])
		shouldSelectBytes[i] = api.Select(e.context.flags.cancelOfferApiFlag, cancelOfferAbiBytes[i], shouldSelectBytes[i])
		shouldSelectBytes[i] = api.Select(e.context.flags.atomicMatchApiFlag, atomicMatchAbiBytes[i], shouldSelectBytes[i])
	}

	return shouldSelectBytes, nil
}

func (e *pureHintAbiEncoder) HintDefaultAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {
	bytes, err := e.ABI.Pack("")
	if err != nil {
		return err
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}

func (e *pureHintAbiEncoder) HintTransferAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {
	bs := make([]byte, 0)
	bs32 := [32]byte{}
	nh := make([]byte, 0)
	nh32 := [32]byte{}

	for _, bi := range inputs[2:34] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		bs = append(bs, uint8(bi.Uint64()))
	}

	for _, bi := range inputs[39:71] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		nh = append(nh, uint8(bi.Uint64()))
	}
	copy(bs32[:], bs)
	copy(nh32[:], nh)

	bytes, err := e.ABI.Pack("Transfer", uint32(inputs[0].Uint64()), uint32(inputs[1].Uint64()), nh32, uint16(inputs[34].Uint64()), inputs[35], uint32(inputs[36].Uint64()), uint16(inputs[37].Uint64()), uint16(inputs[38].Uint64()), bs32, inputs[71].Uint64(), uint32(inputs[72].Uint64()), uint32(inputs[73].Uint64()))
	if err != nil {
		return err
	}
	for i := range results {
		results[i].SetUint64(256)
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}

func (e *pureHintAbiEncoder) HintWithdrawAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {
	aa := make([]byte, 0)
	aa16 := [16]byte{}
	ta := make([]byte, 0)
	ta20 := [20]byte{}

	for _, bi := range inputs[2:18] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		aa = append(aa, uint8(bi.Uint64()))
	}

	for _, bi := range inputs[21:41] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		ta = append(ta, uint8(bi.Uint64()))
	}
	copy(aa16[:], aa)
	copy(ta20[:], ta)

	bytes, err := e.ABI.Pack("Withdraw", (uint32)(inputs[0].Uint64()), (uint16)(inputs[1].Uint64()), aa16, (uint32)(inputs[18].Uint64()), (uint16)(inputs[19].Uint64()), (uint16)(inputs[20].Uint64()), ta20, inputs[41].Uint64(), (uint32)(inputs[42].Uint64()), (uint32)(inputs[43].Uint64()))

	if err != nil {
		return err
	}
	for i := range results {
		results[i].SetUint64(256)
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}

func (e *pureHintAbiEncoder) HintCreateCollectionAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {
	bytes, err := e.ABI.Pack("CreateCollection", (uint32)(inputs[0].Uint64()), (uint32)(inputs[1].Uint64()), (uint16)(inputs[2].Uint64()), (uint16)(inputs[3].Uint64()), inputs[4].Uint64(), (uint32)(inputs[5].Uint64()), (uint32)(inputs[6].Uint64()))
	if err != nil {
		return err
	}
	for i := range results {
		results[i].SetUint64(256)
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}

func (e *pureHintAbiEncoder) HintWithdrawNftAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {
	ta := make([]byte, 0)
	ta20 := [20]byte{}

	for _, bi := range inputs[2:22] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		ta = append(ta, uint8(bi.Uint64()))
	}
	copy(ta20[:], ta)
	bytes, err := e.ABI.Pack("WithdrawNft", (uint32)(inputs[0].Uint64()), inputs[1], ta20, (uint32)(inputs[22].Uint64()), (uint16)(inputs[23].Uint64()), (uint16)(inputs[24].Uint64()), inputs[25].Uint64(), (uint32)(inputs[26].Uint64()), (uint32)(inputs[27].Uint64()))
	if err != nil {
		return err
	}
	for i := range results {
		results[i].SetUint64(256)
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}

func (e *pureHintAbiEncoder) HintTransferNftAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {
	ta := make([]byte, 0)
	ta32 := [32]byte{}

	for _, bi := range inputs[2:34] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		ta = append(ta, uint8(bi.Uint64()))
	}
	copy(ta32[:], ta)

	ch := make([]byte, 0)
	ch32 := [32]byte{}

	for _, bi := range inputs[38:70] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		ch = append(ch, uint8(bi.Uint64()))
	}
	copy(ch32[:], ta)

	bytes, err := e.ABI.Pack("TransferNft", (uint32)(inputs[0].Uint64()), (uint32)(inputs[1].Uint64()), ta32, inputs[34], (uint32)(inputs[35].Uint64()), (uint16)(inputs[36].Uint64()), (uint16)(inputs[37].Uint64()), ch32, inputs[70].Uint64(), (uint32)(inputs[71].Uint64()), (uint32)(inputs[72].Uint64()))
	if err != nil {
		return err
	}
	for i := range results {
		results[i].SetUint64(256)
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}

func (e *pureHintAbiEncoder) HintMintNftAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {
	ta := make([]byte, 0)
	ta32 := [32]byte{}

	for _, bi := range inputs[2:34] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		ta = append(ta, uint8(bi.Uint64()))
	}
	copy(ta32[:], ta)

	ch := make([]byte, 0)
	ch32 := [32]byte{}

	for _, bi := range inputs[34:68] {
		if len(bi.Bytes()) > 1 {
			continue
		}
		ch = append(ch, uint8(bi.Uint64()))
	}
	copy(ch32[:], ta)
	bytes, err := e.ABI.Pack("MintNft", (uint32)(inputs[0].Uint64()), (uint32)(inputs[1].Uint64()), ta32, ch32, (uint32)(inputs[68].Uint64()), (uint16)(inputs[69].Uint64()), (uint16)(inputs[70].Uint64()), (uint32)(inputs[71].Uint64()), (uint32)(inputs[72].Uint64()), inputs[73].Uint64(), (uint32)(inputs[74].Uint64()), (uint32)(inputs[75].Uint64()))
	if err != nil {
		return err
	}
	for i := range results {
		results[i].SetUint64(256)
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}

func (e *pureHintAbiEncoder) HintCancelOfferAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {
	bytes, err := e.ABI.Pack("CancelOffer", (uint32)(inputs[0].Uint64()), inputs[1], (uint32)(inputs[2].Uint64()), (uint16)(inputs[3].Uint64()), (uint16)(inputs[4].Uint64()), inputs[5].Uint64(), (uint32)(inputs[6].Uint64()), (uint32)(inputs[7].Uint64()))
	if err != nil {
		return err
	}
	for i := range results {
		results[i].SetUint64(256)
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}

func (e *pureHintAbiEncoder) HintAtomicMatchAbi(curveId ecc.ID, inputs []*big.Int, results []*big.Int) error {

	buyerOffer := ReadOfferFromArrays(inputs[1:72])
	sellerOffer := ReadOfferFromArrays(inputs[72:143])
	bytes, err := e.ABI.Pack("AtomicMatch", (uint32)(inputs[0].Uint64()), buyerOffer, sellerOffer, (uint32)(inputs[143].Uint64()), (uint16)(inputs[144].Uint64()), (uint16)(inputs[145].Uint64()), inputs[146].Uint64(), (uint32)(inputs[147].Uint64()), (uint32)(inputs[148].Uint64()))
	if err != nil {
		return err
	}
	for i := range results {
		results[i].SetUint64(256)
	}
	for i, b := range bytes {
		results[i].SetUint64(uint64(b))
	}
	return nil
}
