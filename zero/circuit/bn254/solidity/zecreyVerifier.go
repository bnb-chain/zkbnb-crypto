// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package solidity

import (
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// ZecreyVerifierABI is the input ABI used to generate the binding from.
const ZecreyVerifierABI = "[{\"inputs\":[{\"internalType\":\"uint256[2]\",\"name\":\"a\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2][2]\",\"name\":\"b\",\"type\":\"uint256[2][2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"c\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[3]\",\"name\":\"input\",\"type\":\"uint256[3]\"}],\"name\":\"verifyProof\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"r\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"

// ZecreyVerifierBin is the compiled bytecode used for deploying new contracts.
var ZecreyVerifierBin = "0x608060405234801561001057600080fd5b50610f71806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806311479fea14610030575b600080fd5b61012c600480360361016081101561004757600080fd5b6040805180820182529183019291818301918390600290839083908082843760009201829052506040805180820190915293969594608081019493509150600290835b828210156100c8576040805180820182529080840286019060029083908390808284376000920191909152505050815260019091019060200161008a565b5050604080518082018252939695948181019493509150600290839083908082843760009201919091525050604080516060818101909252929594938181019392509060039083908390808284376000920191909152509194506101409350505050565b604080519115158252519081900360200190f35b600061014a610dc3565b6040805180820182528751815260208089015181830152908352815160808101835287515181840190815288518301516060830152815282518084018452888301805151825251830151818401528183015283820152815180830183528651815286820151918101919091529082015260006101c4610648565b604080518082019091526000808252602082015283515191925090600080516020610f1c83398151915211610240576040805162461bcd60e51b815260206004820152601760248201527f76657269666965722d61582d6774652d7072696d652d71000000000000000000604482015290519081900360640190fd5b825160200151600080516020610f1c833981519152116102a7576040805162461bcd60e51b815260206004820152601760248201527f76657269666965722d61592d6774652d7072696d652d71000000000000000000604482015290519081900360640190fd5b60208301515151600080516020610f1c8339815191521161030f576040805162461bcd60e51b815260206004820152601860248201527f76657269666965722d6258302d6774652d7072696d652d710000000000000000604482015290519081900360640190fd5b602083810151015151600080516020610f1c83398151915211610379576040805162461bcd60e51b815260206004820152601860248201527f76657269666965722d6259302d6774652d7072696d652d710000000000000000604482015290519081900360640190fd5b602083810151510151600080516020610f1c833981519152116103e3576040805162461bcd60e51b815260206004820152601860248201527f76657269666965722d6258312d6774652d7072696d652d710000000000000000604482015290519081900360640190fd5b6020838101518101510151600080516020610f1c8339815191521161044f576040805162461bcd60e51b815260206004820152601860248201527f76657269666965722d6259312d6774652d7072696d652d710000000000000000604482015290519081900360640190fd5b604083015151600080516020610f1c833981519152116104b6576040805162461bcd60e51b815260206004820152601760248201527f76657269666965722d63582d6774652d7072696d652d71000000000000000000604482015290519081900360640190fd5b600080516020610f1c83398151915283604001516020015110610520576040805162461bcd60e51b815260206004820152601760248201527f76657269666965722d63592d6774652d7072696d652d71000000000000000000604482015290519081900360640190fd5b60005b60038110156105f4577f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000186826003811061055957fe5b6020020151106105b0576040805162461bcd60e51b815260206004820152601f60248201527f76657269666965722d6774652d736e61726b2d7363616c61722d6669656c6400604482015290519081900360640190fd5b6105ea826105e5856080015184600101600481106105ca57fe5b60200201518985600381106105db57fe5b60200201516109d3565b610a68565b9150600101610523565b50608082015151610606908290610a68565b905061063c6106188460000151610af9565b84602001518460000151856020015185876040015189604001518960600151610b7c565b98975050505050505050565b610650610df5565b6040805180820182527f113a63fe30c86791ed57c95d310b1253259c38c8c8d6ee2ba4cc942b432345b281527f2f96dceefa98e8399c491f3666170db72a1130fd3b256bf7608e40402534e3186020808301919091529083528151608080820184527f015ca21538c7aec480117180d2e0e7da9116820602800d3a8e0907742dcbc21f8285019081527f0b11d317b6bb6a2f165c948669633969c9a60629228f642d4e82b5ffc3c8f188606080850191909152908352845180860186527f1e56f534c81cff138c3aba160614f517e5ad8a3a9b9c88325eee959d0d05150b81527f2a2bf37360c80b45121885d574d39a64e1db84c32880ca8f9f8f62ba17aec24e818601528385015285840192909252835180820185527f2c20fa747ae993c54d8646340e64d5d599b0f8b901d61d0a42f69a26eddb81618186019081527f2bb5574b0570f47722f6dde147810260725c0dbd9bf55e36d834187248ebf361828501528152845180860186527f1e9d902f41285b0abcd49646beb804841eb1f9866c9bbd4e4b8cb407e65a68c981527f0bbb32355de0ddcd0abfad9542ac6fa9de1a898082a551aa048923323475ce82818601528185015285850152835180820185527f05e055507f0ccbeb7a935da2fb14c056c9c565acf8a5f01f9ea917e676a3eaea8186019081527f29d9d0a9582a24ffb0254ec5ac4eed4c73e6cae556e061bb96a61b33f06f5c5c828501528152845180860186527f247c2337253f855e667e38ace9a12bc44c70330d2054d53f8a62a08a3e92caf381527f23d76e169b13c41610cddf02da45414243213c7b28194f12c36914d6e2f143a4818601528185015282860152835180850185527f1166b231f848eed5ce4668c6f255cbbad03714f59df868954468fc29609d595781527f2475c764bce7755184eb9589e89fbf2525176e63337c45f3925feb7c1176552881850152908501805191909152835180850185527f14893a6c4e759a02f5a1c4f0ae9c92a4897bbd2f645dc7bf160469d8f05b7c2e81527f1010990765cd0d09b1a2bf723ab0e26185963ca202d69361bb1a1f8d22c3d3d4818501528151840152835180850185527f071e354a7ec6fa0f700e66198dab717d0890c5af25bb80af92a2bc4815e816b881527f168da7e498f662ff26f1d4aead27d8258c24a92a48eddc0961f33636401b2a8881850152815185015283518085019094526000808552928401929092529051015290565b6109db610e3c565b6109e3610e56565b835181526020808501519082015260408101839052600060608360808460076107d05a03fa9050808015610a1657610a18565bfe5b5080610a60576040805162461bcd60e51b81526020600482015260126024820152711c185a5c9a5b99cb5b5d5b0b59985a5b195960721b604482015290519081900360640190fd5b505092915050565b610a70610e3c565b610a78610e74565b8351815260208085015181830152835160408301528301516060808301919091526000908360c08460066107d05a03fa9050808015610a16575080610a60576040805162461bcd60e51b81526020600482015260126024820152711c185a5c9a5b99cb5859190b59985a5b195960721b604482015290519081900360640190fd5b610b01610e3c565b8151158015610b1257506020820151155b15610b3157506040805180820190915260008082526020820152610b77565b604051806040016040528083600001518152602001600080516020610f1c833981519152846020015181610b6157fe5b06600080516020610f1c83398151915203905290505b919050565b60408051608080820183528a825260208083018a90528284018890526060808401879052845192830185528b83528282018a9052828501889052820185905283516018808252610320820190955260009491859190839082016103008036833701905050905060005b6004811015610d3c5760068102858260048110610bfe57fe5b6020020151518351849083908110610c1257fe5b602002602001018181525050858260048110610c2a57fe5b602002015160200151838260010181518110610c4257fe5b602002602001018181525050848260048110610c5a57fe5b602002015151518351849060028401908110610c7257fe5b602002602001018181525050848260048110610c8a57fe5b60200201515160016020020151838260030181518110610ca657fe5b602002602001018181525050848260048110610cbe57fe5b602002015160200151600060028110610cd357fe5b6020020151838260040181518110610ce757fe5b602002602001018181525050848260048110610cff57fe5b602002015160200151600160028110610d1457fe5b6020020151838260050181518110610d2857fe5b602090810291909101015250600101610be5565b50610d45610e92565b6000602082602086026020860160086107d05a03fa9050808015610a16575080610dae576040805162461bcd60e51b81526020600482015260156024820152741c185a5c9a5b99cb5bdc18dbd9194b59985a5b1959605a1b604482015290519081900360640190fd5b505115159d9c50505050505050505050505050565b6040518060600160405280610dd6610e3c565b8152602001610de3610eb0565b8152602001610df0610e3c565b905290565b6040518060a00160405280610e08610e3c565b8152602001610e15610eb0565b8152602001610e22610eb0565b8152602001610e2f610eb0565b8152602001610df0610ed0565b604051806040016040528060008152602001600081525090565b60405180606001604052806003906020820280368337509192915050565b60405180608001604052806004906020820280368337509192915050565b60405180602001604052806001906020820280368337509192915050565b6040518060400160405280610ec3610efd565b8152602001610df0610efd565b60405180608001604052806004905b610ee7610e3c565b815260200190600190039081610edf5790505090565b6040518060400160405280600290602082028036833750919291505056fe30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47a26469706673582212204c7d58d50ced2135c0ea06ab3dff46fd69edabbf19fe322dfab575d4cf7ac6d664736f6c63430007060033"

// DeployZecreyVerifier deploys a new Ethereum contract, binding an instance of ZecreyVerifier to it.
func DeployZecreyVerifier(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ZecreyVerifier, error) {
	parsed, err := abi.JSON(strings.NewReader(ZecreyVerifierABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(ZecreyVerifierBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ZecreyVerifier{ZecreyVerifierCaller: ZecreyVerifierCaller{contract: contract}, ZecreyVerifierTransactor: ZecreyVerifierTransactor{contract: contract}, ZecreyVerifierFilterer: ZecreyVerifierFilterer{contract: contract}}, nil
}

// ZecreyVerifier is an auto generated Go binding around an Ethereum contract.
type ZecreyVerifier struct {
	ZecreyVerifierCaller     // Read-only binding to the contract
	ZecreyVerifierTransactor // Write-only binding to the contract
	ZecreyVerifierFilterer   // Log filterer for contract events
}

// ZecreyVerifierCaller is an auto generated read-only Go binding around an Ethereum contract.
type ZecreyVerifierCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ZecreyVerifierTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ZecreyVerifierTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ZecreyVerifierFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ZecreyVerifierFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ZecreyVerifierSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ZecreyVerifierSession struct {
	Contract     *ZecreyVerifier   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ZecreyVerifierCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ZecreyVerifierCallerSession struct {
	Contract *ZecreyVerifierCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// ZecreyVerifierTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ZecreyVerifierTransactorSession struct {
	Contract     *ZecreyVerifierTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// ZecreyVerifierRaw is an auto generated low-level Go binding around an Ethereum contract.
type ZecreyVerifierRaw struct {
	Contract *ZecreyVerifier // Generic contract binding to access the raw methods on
}

// ZecreyVerifierCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ZecreyVerifierCallerRaw struct {
	Contract *ZecreyVerifierCaller // Generic read-only contract binding to access the raw methods on
}

// ZecreyVerifierTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ZecreyVerifierTransactorRaw struct {
	Contract *ZecreyVerifierTransactor // Generic write-only contract binding to access the raw methods on
}

// NewZecreyVerifier creates a new instance of ZecreyVerifier, bound to a specific deployed contract.
func NewZecreyVerifier(address common.Address, backend bind.ContractBackend) (*ZecreyVerifier, error) {
	contract, err := bindZecreyVerifier(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ZecreyVerifier{ZecreyVerifierCaller: ZecreyVerifierCaller{contract: contract}, ZecreyVerifierTransactor: ZecreyVerifierTransactor{contract: contract}, ZecreyVerifierFilterer: ZecreyVerifierFilterer{contract: contract}}, nil
}

// NewZecreyVerifierCaller creates a new read-only instance of ZecreyVerifier, bound to a specific deployed contract.
func NewZecreyVerifierCaller(address common.Address, caller bind.ContractCaller) (*ZecreyVerifierCaller, error) {
	contract, err := bindZecreyVerifier(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ZecreyVerifierCaller{contract: contract}, nil
}

// NewZecreyVerifierTransactor creates a new write-only instance of ZecreyVerifier, bound to a specific deployed contract.
func NewZecreyVerifierTransactor(address common.Address, transactor bind.ContractTransactor) (*ZecreyVerifierTransactor, error) {
	contract, err := bindZecreyVerifier(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ZecreyVerifierTransactor{contract: contract}, nil
}

// NewZecreyVerifierFilterer creates a new log filterer instance of ZecreyVerifier, bound to a specific deployed contract.
func NewZecreyVerifierFilterer(address common.Address, filterer bind.ContractFilterer) (*ZecreyVerifierFilterer, error) {
	contract, err := bindZecreyVerifier(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ZecreyVerifierFilterer{contract: contract}, nil
}

// bindZecreyVerifier binds a generic wrapper to an already deployed contract.
func bindZecreyVerifier(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ZecreyVerifierABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ZecreyVerifier *ZecreyVerifierRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ZecreyVerifier.Contract.ZecreyVerifierCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ZecreyVerifier *ZecreyVerifierRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ZecreyVerifier.Contract.ZecreyVerifierTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ZecreyVerifier *ZecreyVerifierRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ZecreyVerifier.Contract.ZecreyVerifierTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ZecreyVerifier *ZecreyVerifierCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ZecreyVerifier.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ZecreyVerifier *ZecreyVerifierTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ZecreyVerifier.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ZecreyVerifier *ZecreyVerifierTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ZecreyVerifier.Contract.contract.Transact(opts, method, params...)
}

// VerifyProof is a free data retrieval call binding the contract method 0x11479fea.
//
// Solidity: function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[3] input) view returns(bool r)
func (_ZecreyVerifier *ZecreyVerifierCaller) VerifyProof(opts *bind.CallOpts, a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, input [3]*big.Int) (bool, error) {
	var out []interface{}
	err := _ZecreyVerifier.contract.Call(opts, &out, "verifyProof", a, b, c, input)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyProof is a free data retrieval call binding the contract method 0x11479fea.
//
// Solidity: function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[3] input) view returns(bool r)
func (_ZecreyVerifier *ZecreyVerifierSession) VerifyProof(a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, input [3]*big.Int) (bool, error) {
	return _ZecreyVerifier.Contract.VerifyProof(&_ZecreyVerifier.CallOpts, a, b, c, input)
}

// VerifyProof is a free data retrieval call binding the contract method 0x11479fea.
//
// Solidity: function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[3] input) view returns(bool r)
func (_ZecreyVerifier *ZecreyVerifierCallerSession) VerifyProof(a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, input [3]*big.Int) (bool, error) {
	return _ZecreyVerifier.Contract.VerifyProof(&_ZecreyVerifier.CallOpts, a, b, c, input)
}
