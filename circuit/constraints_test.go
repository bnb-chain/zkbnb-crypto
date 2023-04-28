package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"testing"
)

func TestBlockConstraintsCounts(t *testing.T) {
	var blockCircuit BlockConstraints
	blockCircuit.TxsCount = 1
	gasAssetIds := []int64{0, 1}
	gasAccountIndex := int64(1)
	blockCircuit.Txs = make([]TxConstraints, blockCircuit.TxsCount)
	for i := 0; i < blockCircuit.TxsCount; i++ {
		blockCircuit.Txs[i] = GetZeroTxConstraint()
	}
	blockCircuit.GasAssetIds = gasAssetIds
	blockCircuit.GasAccountIndex = gasAccountIndex
	blockCircuit.Gas = GetZeroGasConstraints(gasAssetIds)
	blockCircuit.GKRs.AllocateGKRCircuit(11)

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &blockCircuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		fmt.Println("error occured ", err)
	}
	fmt.Println("block circuit constraints number is ", r1cs.GetNbConstraints())
}
