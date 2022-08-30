package abi

import (
	"github.com/consensys/gnark/frontend"
)

type AbiCircuit struct {
	AbiId  frontend.Variable
	Values []frontend.Variable // variable name
	Bytes  []frontend.Variable `gnark:",public"` // abi object
	Name   frontend.Variable   `gnark:",public"` // For now we are using abiId to select the right bytes for simply. But actually name is taken by the abi.encode.
}

func (circuit *AbiCircuit) Define(api frontend.API) error {
	encoder, err := NewAbiEncoder(api, circuit.AbiId)
	if err != nil {
		return err
	}

	res, err := encoder.Pack(api, circuit.Name, circuit.Values...)
	if err != nil {
		return err
	}

	for i := range res {
		validRes := api.Select(api.IsZero(api.Sub(res[i], 256)), 0, res[i])
		api.AssertIsEqual(validRes, circuit.Bytes[i])
	}
	return nil
}
