package abi

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type Offer struct {
	OfferType      uint8
	OfferId        *big.Int
	AccountIndex   uint32
	NftIndex       uint32
	PackedAmount   *big.Int
	OfferListedAt  uint64
	OfferExpiredAt uint64
	SigRx          [16]byte
	SigRy          [16]byte
	SigS           [32]byte
}

type OfferConstraint struct {
	OfferType      frontend.Variable
	OfferId        frontend.Variable
	AccountIndex   frontend.Variable
	NftIndex       frontend.Variable
	PackedAmount   frontend.Variable
	OfferListedAt  frontend.Variable
	OfferExpiredAt frontend.Variable
	SigRx          [16]frontend.Variable
	SigRy          [16]frontend.Variable
	SigS           [32]frontend.Variable
}

func (oc OfferConstraint) DecomposeConstraint() *Offer {

	sigRx := [16]byte{}
	sigRy := [16]byte{}
	sigS := [32]byte{}
	for i := 0; i < 16; i++ {
		sigRx[i] = oc.SigRx[i].(byte)
		sigRy[i] = oc.SigRy[i].(byte)
	}
	for i := 0; i < 32; i++ {
		sigS[i] = oc.SigS[i].(byte)
	}

	offer := Offer{
		OfferType:      oc.OfferType.(uint8),
		OfferId:        oc.OfferId.(*big.Int),
		AccountIndex:   oc.AccountIndex.(uint32),
		NftIndex:       oc.NftIndex.(uint32),
		PackedAmount:   oc.PackedAmount.(*big.Int),
		OfferListedAt:  oc.OfferListedAt.(uint64),
		OfferExpiredAt: oc.OfferExpiredAt.(uint64),
		SigRx:          sigRx,
		SigRy:          sigRy,
		SigS:           sigS,
	}

	return &offer
}

func (oc OfferConstraint) DecomposeConstraintArrays() []frontend.Variable {

	ret := make([]frontend.Variable, 71)
	ret[0] = oc.OfferType.(uint8)
	ret[1] = oc.OfferId.(*big.Int)
	ret[2] = oc.AccountIndex.(uint32)
	ret[3] = oc.NftIndex.(uint32)
	ret[4] = oc.PackedAmount.(*big.Int)
	ret[5] = oc.OfferListedAt.(uint64)
	ret[6] = oc.OfferExpiredAt.(uint64)
	copy(ret[7:], oc.SigRx[:])
	copy(ret[23:], oc.SigRy[:])
	copy(ret[39:], oc.SigS[:])

	return ret
}

func ReadOfferFromArrays(arrays []*big.Int) *Offer {
	sigRx := [16]byte{}
	sigRy := [16]byte{}
	sigS := [32]byte{}
	for i := 0; i < 16; i++ {
		sigRx[i] = (byte)(arrays[7+i].Uint64())
		sigRy[i] = (byte)(arrays[23+i].Uint64())
	}
	for i := 0; i < 32; i++ {
		sigS[i] = (byte)(arrays[39+i].Uint64())
	}
	offer := Offer{
		OfferType:      (uint8)(arrays[0].Uint64()),
		OfferId:        arrays[1],
		AccountIndex:   (uint32)(arrays[2].Uint64()),
		NftIndex:       (uint32)(arrays[3].Uint64()),
		PackedAmount:   arrays[4],
		OfferListedAt:  arrays[5].Uint64(),
		OfferExpiredAt: arrays[6].Uint64(),
		SigRx:          sigRx,
		SigRy:          sigRy,
		SigS:           sigS,
	}

	return &offer
}
