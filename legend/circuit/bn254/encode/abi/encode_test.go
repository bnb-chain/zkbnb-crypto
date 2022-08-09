// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package abi

import (
	"fmt"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	abi2 "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestAbiEncodeTransfer(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(TransferAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	bytesFirst := [32]byte{'0'}
	wrappedFirst := WrapToAbiBytes32(bytesFirst)
	for i := range wrappedFirst {
		w.Values[2+i] = wrappedFirst[i]
	}
	w.Values[34] = uint16(1)
	w.Values[35] = uint64(1)
	w.Values[36] = uint32(1)
	w.Values[37] = uint16(1)
	w.Values[38] = uint16(1)

	bytesLast := [32]byte{'0'}
	wrappedLast := WrapToAbiBytes32(bytesLast)
	for i := range wrappedLast {
		w.Values[39+i] = wrappedLast[i]
	}

	w.Values[71] = uint32(1)
	w.Values[72] = uint32(1)
	w.Values[73] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("Transfer", w.Values[0].(uint32), w.Values[1].(uint32), bytesFirst, w.Values[34].(uint16), new(big.Int).SetUint64(w.Values[35].(uint64)), w.Values[36].(uint32), w.Values[37].(uint16), w.Values[38].(uint16), bytesLast, w.Values[71].(uint32), w.Values[72].(uint32), w.Values[73].(uint32))
	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func DefaultCircuit() (circuit Circuit) {
	circuit.AbiId = 0
	circuit.Values = make([]frontend.Variable, 255)
	circuit.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(circuit.Values); i++ {
		circuit.Values[i] = 0
		circuit.Bytes[i] = 0
	}
	circuit.Name = 1
	return circuit
}

func TestAbiEncodeWithdraw(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(WithdrawAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint16(1)

	bytesFirst := [16]byte{'0'}
	wrappedFirst := WrapToAbiBytes16(bytesFirst)
	for i := range wrappedFirst {
		w.Values[2+i] = wrappedFirst[i]
	}
	w.Values[18] = uint32(1)
	w.Values[19] = uint16(1)
	w.Values[20] = uint16(1)

	bytesLast := [32]byte{'0'}
	wrappedLast := WrapToAbiBytes32(bytesLast)
	for i := range wrappedLast {
		w.Values[21+i] = wrappedLast[i]
	}

	w.Values[53] = uint32(1)
	w.Values[54] = uint32(1)
	w.Values[55] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("Withdraw", w.Values[0].(uint32), w.Values[1].(uint16), bytesFirst, w.Values[18].(uint32), w.Values[19].(uint16), w.Values[20].(uint16), bytesLast, w.Values[53].(uint32), w.Values[54].(uint32), w.Values[55].(uint32))
	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeAddLiquidity(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(AddLiquidityAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint16(1)
	w.Values[2] = uint64(1)
	w.Values[3] = uint64(1)
	w.Values[4] = uint32(1)
	w.Values[5] = uint16(1)
	w.Values[6] = uint16(1)
	w.Values[7] = uint32(1)
	w.Values[8] = uint32(1)
	w.Values[9] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("AddLiquidity", w.Values[0].(uint32), w.Values[1].(uint16), new(big.Int).SetUint64(w.Values[2].(uint64)), new(big.Int).SetUint64(w.Values[3].(uint64)), w.Values[4].(uint32), w.Values[5].(uint16), w.Values[6].(uint16), w.Values[7].(uint32), w.Values[8].(uint32), w.Values[9].(uint32))
	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeRemoveLiquidity(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(RemoveLiquidityAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint16(1)
	w.Values[2] = uint64(1)
	w.Values[3] = uint64(1)
	w.Values[4] = uint64(1)
	w.Values[5] = uint32(1)
	w.Values[6] = uint16(1)
	w.Values[7] = uint16(1)
	w.Values[8] = uint32(1)
	w.Values[9] = uint32(1)
	w.Values[10] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("RemoveLiquidity", w.Values[0].(uint32), w.Values[1].(uint16), new(big.Int).SetUint64(w.Values[2].(uint64)), new(big.Int).SetUint64(w.Values[3].(uint64)), new(big.Int).SetUint64(w.Values[4].(uint64)), w.Values[5].(uint32), w.Values[6].(uint16), w.Values[7].(uint16), w.Values[8].(uint32), w.Values[9].(uint32), w.Values[10].(uint32))
	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeSwap(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(SwapAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint16(1)
	w.Values[2] = uint64(1)
	w.Values[3] = uint64(1)
	w.Values[4] = uint32(1)
	w.Values[5] = uint16(1)
	w.Values[6] = uint16(1)
	w.Values[7] = uint32(1)
	w.Values[8] = uint32(1)
	w.Values[9] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("Swap", w.Values[0].(uint32), w.Values[1].(uint16), new(big.Int).SetUint64(w.Values[2].(uint64)), new(big.Int).SetUint64(w.Values[3].(uint64)), w.Values[4].(uint32), w.Values[5].(uint16), w.Values[6].(uint16), w.Values[7].(uint32), w.Values[8].(uint32), w.Values[9].(uint32))

	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeCreateCollection(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(CreateCollectionAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	w.Values[2] = uint16(1)
	w.Values[3] = uint16(1)
	w.Values[4] = uint32(1)
	w.Values[5] = uint32(1)
	w.Values[6] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("CreateCollection", w.Values[0].(uint32), w.Values[1].(uint32), w.Values[2].(uint16), w.Values[3].(uint16), w.Values[4].(uint32), w.Values[5].(uint32), w.Values[6].(uint32))

	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeWithdrawNft(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(WithdrawNftAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = new(big.Int).SetUint64(1)
	bytesLast := [32]byte{'0'}
	wrappedLast := WrapToAbiBytes32(bytesLast)
	for i := range wrappedLast {
		w.Values[2+i] = wrappedLast[i]
	}
	w.Values[34] = uint32(1)
	w.Values[35] = uint16(1)
	w.Values[36] = uint16(1)
	w.Values[37] = uint32(1)
	w.Values[38] = uint32(1)
	w.Values[39] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("WithdrawNft", w.Values[0].(uint32), w.Values[1], bytesLast, w.Values[34].(uint32), w.Values[35].(uint16), w.Values[36].(uint16), w.Values[37].(uint32), w.Values[38].(uint32), w.Values[39].(uint32))
	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeTransferNft(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(TransferNftAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	bytesFirst := [32]byte{'0'}
	wrappedFirst := WrapToAbiBytes32(bytesFirst)
	for i := range wrappedFirst {
		w.Values[2+i] = wrappedFirst[i]
	}
	w.Values[34] = new(big.Int).SetUint64(1)
	w.Values[35] = uint32(1)
	w.Values[36] = uint16(1)
	w.Values[37] = uint16(1)
	bytesLast := [32]byte{'0'}
	wrappedLast := WrapToAbiBytes32(bytesLast)
	for i := range wrappedLast {
		w.Values[38+i] = wrappedLast[i]
	}
	w.Values[70] = uint32(1)
	w.Values[71] = uint32(1)
	w.Values[72] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("TransferNft", w.Values[0].(uint32), w.Values[1].(uint32), bytesFirst, w.Values[34], w.Values[35].(uint32), w.Values[36].(uint16), w.Values[37].(uint16), bytesLast, w.Values[70].(uint32), w.Values[71].(uint32), w.Values[72].(uint32))

	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeMintNft(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(MintNftAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	bytesFirst := [32]byte{'0'}
	wrappedFirst := WrapToAbiBytes32(bytesFirst)
	for i := range wrappedFirst {
		w.Values[2+i] = wrappedFirst[i]
	}
	bytesLast := [32]byte{'0'}
	wrappedLast := WrapToAbiBytes32(bytesLast)
	for i := range wrappedLast {
		w.Values[34+i] = wrappedLast[i]
	}
	w.Values[68] = uint32(1)
	w.Values[69] = uint16(1)
	w.Values[70] = uint16(1)
	w.Values[71] = uint32(1)
	w.Values[72] = uint32(1)
	w.Values[73] = uint32(1)
	w.Values[74] = uint32(1)
	w.Values[75] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("MintNft", w.Values[0].(uint32), w.Values[1].(uint32), bytesFirst, bytesLast, w.Values[68].(uint32), w.Values[69].(uint16), w.Values[70].(uint16), w.Values[71].(uint32), w.Values[72].(uint32), w.Values[73].(uint32), w.Values[74].(uint32), w.Values[75].(uint32))

	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeCancelOffer(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(CancelOfferAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint64(1)
	w.Values[2] = uint32(1)
	w.Values[3] = uint16(1)
	w.Values[4] = uint16(1)
	w.Values[5] = uint32(1)
	w.Values[6] = uint32(1)
	w.Values[7] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("CancelOffer", w.Values[0].(uint32), new(big.Int).SetUint64(w.Values[1].(uint64)), w.Values[2].(uint32), w.Values[3].(uint16), w.Values[4].(uint16), w.Values[5].(uint32), w.Values[6].(uint32), w.Values[7].(uint32))

	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestAbiEncodeAtomicMatch(t *testing.T) {
	// Compile circuit
	var circuit Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.AbiId = int(AtomicMatchAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Bytes = make([]frontend.Variable, StaticArgsOutput)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	rx := [16]frontend.Variable{}
	ry := [16]frontend.Variable{}
	s := [32]frontend.Variable{}
	for i := 0; i < 16; i++ {
		rx[i] = uint8(0x1)
		ry[i] = uint8(0x1)
	}
	for i := 0; i < 32; i++ {
		s[i] = uint8(0x1)
	}
	w.Values[0] = uint32(1)
	offer := OfferConstraint{
		OfferType:      uint8(1),
		OfferId:        new(big.Int).SetUint64(1),
		AccountIndex:   uint32(1),
		NftIndex:       uint32(1),
		PackedAmount:   new(big.Int).SetUint64(1),
		OfferListedAt:  uint64(1),
		OfferExpiredAt: uint64(1),
		SigRx:          rx,
		SigRy:          ry,
		SigS:           s,
	}
	offerArray := offer.DecomposeConstraintArrays()
	for i, _ := range offerArray {
		w.Values[1+i] = offerArray[i]
	}
	for i, _ := range offerArray {
		w.Values[72+i] = offerArray[i]
	}
	w.Values[143] = uint32(1)
	w.Values[144] = uint16(1)
	w.Values[145] = uint16(1)
	w.Values[146] = uint32(1)
	w.Values[147] = uint32(1)
	w.Values[148] = uint32(1)

	a, err := abi2.JSON(strings.NewReader(GeneralABIJSON))
	assert.NoError(t, err)

	b, err := a.Pack("AtomicMatch", w.Values[0].(uint32), offer.DecomposeConstraint(), offer.DecomposeConstraint(), w.Values[143].(uint32), w.Values[144].(uint16), w.Values[145].(uint16), w.Values[146].(uint32), w.Values[147].(uint32), w.Values[148].(uint32))

	assert.NoError(t, err)

	i := 0
	for ; i < len(b) && i < StaticArgsOutput; i++ {
		w.Bytes[i] = b[i]
	}

	for ; i < StaticArgsOutput; i++ {
		w.Bytes[i] = 0
	}
	w.Name = 1

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}
