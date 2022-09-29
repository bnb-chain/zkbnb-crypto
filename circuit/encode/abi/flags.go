package abi

import (
	"github.com/consensys/gnark/frontend"
)

type Context struct {
	flags Flags
	api   frontend.API
}

type Flags struct {
	defaultApiFlag          frontend.Variable
	transferApiFlag         frontend.Variable
	withdrawApiFlag         frontend.Variable
	createCollectionApiFlag frontend.Variable
	withdrawNftApiFlag      frontend.Variable
	transferNftApiFlag      frontend.Variable
	mintNftApiFlag          frontend.Variable
	atomicMatchApiFlag      frontend.Variable
	cancelOfferApiFlag      frontend.Variable
}

func NewContext(api frontend.API, defaultApiFlag,
	transferApiFlag frontend.Variable,
	withdrawApiFlag frontend.Variable,
	createCollectionApiFlag frontend.Variable,
	withdrawNftApiFlag frontend.Variable,
	transferNftApiFlag frontend.Variable,
	mintNftApiFlag frontend.Variable,
	atomicMatchApiFlag frontend.Variable,
	cancelOfferApiFlag frontend.Variable,
) Context {
	return Context{flags: Flags{
		defaultApiFlag:          defaultApiFlag,
		transferApiFlag:         transferApiFlag,
		withdrawApiFlag:         withdrawApiFlag,
		createCollectionApiFlag: createCollectionApiFlag,
		withdrawNftApiFlag:      withdrawNftApiFlag,
		transferNftApiFlag:      transferNftApiFlag,
		mintNftApiFlag:          mintNftApiFlag,
		atomicMatchApiFlag:      atomicMatchApiFlag,
		cancelOfferApiFlag:      cancelOfferApiFlag,
	}, api: api}
}
