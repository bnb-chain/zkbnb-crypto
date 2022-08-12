package abi

import (
	"github.com/consensys/gnark/frontend"
)

func NewAbiEncoder(api frontend.API, abiId frontend.Variable) (AbiEncoder, error) {
	defaultApiFlag := api.IsZero(api.Sub(abiId, int(DefaultAbi)))
	transferApiFlag := api.IsZero(api.Sub(abiId, int(TransferAbi)))
	withdrawApiFlag := api.IsZero(api.Sub(abiId, int(WithdrawAbi)))
	addLiquidityApiFlag := api.IsZero(api.Sub(abiId, int(AddLiquidityAbi)))
	removeLiquidityApiFlag := api.IsZero(api.Sub(abiId, int(RemoveLiquidityAbi)))
	swapApiFlag := api.IsZero(api.Sub(abiId, int(SwapAbi)))
	createCollectionApiFlag := api.IsZero(api.Sub(abiId, int(CreateCollectionAbi)))
	withdrawNftApiFlag := api.IsZero(api.Sub(abiId, int(WithdrawNftAbi)))
	transferNftApiFlag := api.IsZero(api.Sub(abiId, int(TransferNftAbi)))
	mintNftApiFlag := api.IsZero(api.Sub(abiId, int(MintNftAbi)))
	atomicMatchApiFlag := api.IsZero(api.Sub(abiId, int(AtomicMatchAbi)))
	cancelOfferApiFlag := api.IsZero(api.Sub(abiId, int(CancelOfferAbi)))
	context := NewContext(api, defaultApiFlag, transferApiFlag, withdrawApiFlag, addLiquidityApiFlag,
		removeLiquidityApiFlag, swapApiFlag, createCollectionApiFlag, withdrawNftApiFlag, transferNftApiFlag,
		mintNftApiFlag, atomicMatchApiFlag, cancelOfferApiFlag)
	return NewPureAbiEncoder(context)
}
