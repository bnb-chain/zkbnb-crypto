package wasm

import (
	"encoding/json"
	"syscall/js"
	"time"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	ProveWithdraw: helper function for the frontend for building withdraw tx
	@tokenId: token id
	@accountId: account index
	@segmentInfo: segmentInfo JSON string
*/
func ProveWithdraw() js.Func {
	proveWithdrawFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 3
		if len(args) != 3 {
			return ErrInvalidWithdrawParams
		}
		// read tokenId
		tokenId := args[0].Int()
		if tokenId <= 0 {
			return ErrInvalidWithdrawParams
		}
		// transfer tokenId to uint32
		tId := uint32(tokenId)
		// read accountId
		accountId := args[1].Int()
		// read segmentInfo JSON str
		segmentInfo := args[2].String()
		// parse segmentInfo
		segment, errNum := FromWithdrawSegmentJSON(segmentInfo)
		if errNum != Success {
			return errNum
		}
		// create withdraw relation
		relation, err := zecrey.NewWithdrawRelation(segment.EncVal, segment.Pk, segment.BStar, segment.Sk, tId)
		if err != nil {
			return ErrInvalidWithdrawRelationParams
		}
		// create withdraw proof
		withdrawProof, err := zecrey.ProveWithdraw(relation)
		if err != nil {
			return ErrProveWithdraw
		}
		withdrawTx := &WithdrawTransactionAo{
			TokenId:   tId,
			AccountId: accountId,
			Proof:     withdrawProof,
			CreateAt:  time.Now().Unix(),
		}
		txBytes, err := json.Marshal(withdrawTx)
		if err != nil {
			return ErrMarshalTx
		}
		return string(txBytes)
	})
	return proveWithdrawFunc
}

/*
	ProveTransfer: prove privacy transfer
	@tokenId: token id
	@accountIdsStr: string of int array represents account indexes
	@segmentInfosStr: string of segmentInfo array, which are used to generate the transfer proof
*/
func ProveTransfer() js.Func {
	proveTransferFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 3 {
			return ErrInvalidTransferParams
		}
		// read token id
		tokenId := args[0].Int()
		if tokenId <= 0 {
			return ErrInvalidTransferParams
		}
		tId := uint32(tokenId)
		// read accountIds Str
		accountIdsStr := args[1].String()
		// read segmentInfo Str
		segmentInfosStr := args[2].String()

		// parse accountIds: []int
		var accountIds []int
		err := json.Unmarshal([]byte(accountIdsStr), &accountIds)
		if err != nil {
			return ErrInvalidTransferParams
		}
		// parse segmentInfo: []PTransferSegment
		segments, errNum := FromPTransferSegmentJSON(segmentInfosStr)
		if errNum != Success {
			return errNum
		}
		relation, err := zecrey.NewPTransferProofRelation(tId)
		if err != nil {
			return ErrInvalidTransferRelationParams
		}
		for _, segment := range segments {
			err := relation.AddStatement(segment.EncVal, segment.Pk, segment.BDelta, segment.Sk)
			if err != nil {
				return ErrInvalidTransferRelationParams
			}
		}
		transferProof, err := zecrey.ProvePTransfer(relation)
		if err != nil {
			return ErrProveTransfer
		}
		tx := &TransferTransactionAo{
			// token id
			TokenId: tId,
			// account indexes
			AccountIds: accountIds,
			// transfer proof
			Proof: transferProof,
			// create time
			CreateAt: time.Now().Unix(),
		}
		txBytes, err := json.Marshal(tx)
		if err != nil {
			return ErrMarshalTx
		}
		return string(txBytes)
	})
	return proveTransferFunc
}
