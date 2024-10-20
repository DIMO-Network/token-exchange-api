// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package sacd

import (
	"errors"
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
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// SacdMetaData contains all meta data concerning the Sacd contract.
var SacdMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"InvalidTokenId\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"Unauthorized\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ZeroAddress\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"}],\"name\":\"PermissionsSet\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"}],\"name\":\"getPermissions\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint8\",\"name\":\"permissionIndex\",\"type\":\"uint8\"}],\"name\":\"hasPermission\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"}],\"name\":\"hasPermissions\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"onTransfer\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"version\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"}],\"name\":\"permissionRecords\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"}],\"name\":\"setPermissions\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"tokenIdToVersion\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"version\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// SacdABI is the input ABI used to generate the binding from.
// Deprecated: Use SacdMetaData.ABI instead.
var SacdABI = SacdMetaData.ABI

// Sacd is an auto generated Go binding around an Ethereum contract.
type Sacd struct {
	SacdCaller     // Read-only binding to the contract
	SacdTransactor // Write-only binding to the contract
	SacdFilterer   // Log filterer for contract events
}

// SacdCaller is an auto generated read-only Go binding around an Ethereum contract.
type SacdCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SacdTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SacdTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SacdFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SacdFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SacdSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SacdSession struct {
	Contract     *Sacd             // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SacdCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SacdCallerSession struct {
	Contract *SacdCaller   // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// SacdTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SacdTransactorSession struct {
	Contract     *SacdTransactor   // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SacdRaw is an auto generated low-level Go binding around an Ethereum contract.
type SacdRaw struct {
	Contract *Sacd // Generic contract binding to access the raw methods on
}

// SacdCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SacdCallerRaw struct {
	Contract *SacdCaller // Generic read-only contract binding to access the raw methods on
}

// SacdTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SacdTransactorRaw struct {
	Contract *SacdTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSacd creates a new instance of Sacd, bound to a specific deployed contract.
func NewSacd(address common.Address, backend bind.ContractBackend) (*Sacd, error) {
	contract, err := bindSacd(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Sacd{SacdCaller: SacdCaller{contract: contract}, SacdTransactor: SacdTransactor{contract: contract}, SacdFilterer: SacdFilterer{contract: contract}}, nil
}

// NewSacdCaller creates a new read-only instance of Sacd, bound to a specific deployed contract.
func NewSacdCaller(address common.Address, caller bind.ContractCaller) (*SacdCaller, error) {
	contract, err := bindSacd(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SacdCaller{contract: contract}, nil
}

// NewSacdTransactor creates a new write-only instance of Sacd, bound to a specific deployed contract.
func NewSacdTransactor(address common.Address, transactor bind.ContractTransactor) (*SacdTransactor, error) {
	contract, err := bindSacd(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SacdTransactor{contract: contract}, nil
}

// NewSacdFilterer creates a new log filterer instance of Sacd, bound to a specific deployed contract.
func NewSacdFilterer(address common.Address, filterer bind.ContractFilterer) (*SacdFilterer, error) {
	contract, err := bindSacd(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SacdFilterer{contract: contract}, nil
}

// bindSacd binds a generic wrapper to an already deployed contract.
func bindSacd(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := SacdMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Sacd *SacdRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Sacd.Contract.SacdCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Sacd *SacdRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Sacd.Contract.SacdTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Sacd *SacdRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Sacd.Contract.SacdTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Sacd *SacdCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Sacd.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Sacd *SacdTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Sacd.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Sacd *SacdTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Sacd.Contract.contract.Transact(opts, method, params...)
}

// GetPermissions is a free data retrieval call binding the contract method 0x68233c61.
//
// Solidity: function getPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions) view returns(uint256)
func (_Sacd *SacdCaller) GetPermissions(opts *bind.CallOpts, asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "getPermissions", asset, tokenId, grantee, permissions)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetPermissions is a free data retrieval call binding the contract method 0x68233c61.
//
// Solidity: function getPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions) view returns(uint256)
func (_Sacd *SacdSession) GetPermissions(asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	return _Sacd.Contract.GetPermissions(&_Sacd.CallOpts, asset, tokenId, grantee, permissions)
}

// GetPermissions is a free data retrieval call binding the contract method 0x68233c61.
//
// Solidity: function getPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions) view returns(uint256)
func (_Sacd *SacdCallerSession) GetPermissions(asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	return _Sacd.Contract.GetPermissions(&_Sacd.CallOpts, asset, tokenId, grantee, permissions)
}

// HasPermission is a free data retrieval call binding the contract method 0x48eb48f5.
//
// Solidity: function hasPermission(address asset, uint256 tokenId, address grantee, uint8 permissionIndex) view returns(bool)
func (_Sacd *SacdCaller) HasPermission(opts *bind.CallOpts, asset common.Address, tokenId *big.Int, grantee common.Address, permissionIndex uint8) (bool, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "hasPermission", asset, tokenId, grantee, permissionIndex)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasPermission is a free data retrieval call binding the contract method 0x48eb48f5.
//
// Solidity: function hasPermission(address asset, uint256 tokenId, address grantee, uint8 permissionIndex) view returns(bool)
func (_Sacd *SacdSession) HasPermission(asset common.Address, tokenId *big.Int, grantee common.Address, permissionIndex uint8) (bool, error) {
	return _Sacd.Contract.HasPermission(&_Sacd.CallOpts, asset, tokenId, grantee, permissionIndex)
}

// HasPermission is a free data retrieval call binding the contract method 0x48eb48f5.
//
// Solidity: function hasPermission(address asset, uint256 tokenId, address grantee, uint8 permissionIndex) view returns(bool)
func (_Sacd *SacdCallerSession) HasPermission(asset common.Address, tokenId *big.Int, grantee common.Address, permissionIndex uint8) (bool, error) {
	return _Sacd.Contract.HasPermission(&_Sacd.CallOpts, asset, tokenId, grantee, permissionIndex)
}

// HasPermissions is a free data retrieval call binding the contract method 0x16bc016c.
//
// Solidity: function hasPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions) view returns(bool)
func (_Sacd *SacdCaller) HasPermissions(opts *bind.CallOpts, asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int) (bool, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "hasPermissions", asset, tokenId, grantee, permissions)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasPermissions is a free data retrieval call binding the contract method 0x16bc016c.
//
// Solidity: function hasPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions) view returns(bool)
func (_Sacd *SacdSession) HasPermissions(asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int) (bool, error) {
	return _Sacd.Contract.HasPermissions(&_Sacd.CallOpts, asset, tokenId, grantee, permissions)
}

// HasPermissions is a free data retrieval call binding the contract method 0x16bc016c.
//
// Solidity: function hasPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions) view returns(bool)
func (_Sacd *SacdCallerSession) HasPermissions(asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int) (bool, error) {
	return _Sacd.Contract.HasPermissions(&_Sacd.CallOpts, asset, tokenId, grantee, permissions)
}

// PermissionRecords is a free data retrieval call binding the contract method 0x15e7d96b.
//
// Solidity: function permissionRecords(address asset, uint256 tokenId, uint256 version, address grantee) view returns(uint256 permissions, uint256 expiration, string source)
func (_Sacd *SacdCaller) PermissionRecords(opts *bind.CallOpts, asset common.Address, tokenId *big.Int, version *big.Int, grantee common.Address) (struct {
	Permissions *big.Int
	Expiration  *big.Int
	Source      string
}, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "permissionRecords", asset, tokenId, version, grantee)

	outstruct := new(struct {
		Permissions *big.Int
		Expiration  *big.Int
		Source      string
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Permissions = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.Expiration = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.Source = *abi.ConvertType(out[2], new(string)).(*string)

	return *outstruct, err

}

// PermissionRecords is a free data retrieval call binding the contract method 0x15e7d96b.
//
// Solidity: function permissionRecords(address asset, uint256 tokenId, uint256 version, address grantee) view returns(uint256 permissions, uint256 expiration, string source)
func (_Sacd *SacdSession) PermissionRecords(asset common.Address, tokenId *big.Int, version *big.Int, grantee common.Address) (struct {
	Permissions *big.Int
	Expiration  *big.Int
	Source      string
}, error) {
	return _Sacd.Contract.PermissionRecords(&_Sacd.CallOpts, asset, tokenId, version, grantee)
}

// PermissionRecords is a free data retrieval call binding the contract method 0x15e7d96b.
//
// Solidity: function permissionRecords(address asset, uint256 tokenId, uint256 version, address grantee) view returns(uint256 permissions, uint256 expiration, string source)
func (_Sacd *SacdCallerSession) PermissionRecords(asset common.Address, tokenId *big.Int, version *big.Int, grantee common.Address) (struct {
	Permissions *big.Int
	Expiration  *big.Int
	Source      string
}, error) {
	return _Sacd.Contract.PermissionRecords(&_Sacd.CallOpts, asset, tokenId, version, grantee)
}

// TokenIdToVersion is a free data retrieval call binding the contract method 0xeba57928.
//
// Solidity: function tokenIdToVersion(address asset, uint256 tokenId) view returns(uint256 version)
func (_Sacd *SacdCaller) TokenIdToVersion(opts *bind.CallOpts, asset common.Address, tokenId *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "tokenIdToVersion", asset, tokenId)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TokenIdToVersion is a free data retrieval call binding the contract method 0xeba57928.
//
// Solidity: function tokenIdToVersion(address asset, uint256 tokenId) view returns(uint256 version)
func (_Sacd *SacdSession) TokenIdToVersion(asset common.Address, tokenId *big.Int) (*big.Int, error) {
	return _Sacd.Contract.TokenIdToVersion(&_Sacd.CallOpts, asset, tokenId)
}

// TokenIdToVersion is a free data retrieval call binding the contract method 0xeba57928.
//
// Solidity: function tokenIdToVersion(address asset, uint256 tokenId) view returns(uint256 version)
func (_Sacd *SacdCallerSession) TokenIdToVersion(asset common.Address, tokenId *big.Int) (*big.Int, error) {
	return _Sacd.Contract.TokenIdToVersion(&_Sacd.CallOpts, asset, tokenId)
}

// OnTransfer is a paid mutator transaction binding the contract method 0xe81e9b64.
//
// Solidity: function onTransfer(address asset, uint256 tokenId) returns()
func (_Sacd *SacdTransactor) OnTransfer(opts *bind.TransactOpts, asset common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "onTransfer", asset, tokenId)
}

// OnTransfer is a paid mutator transaction binding the contract method 0xe81e9b64.
//
// Solidity: function onTransfer(address asset, uint256 tokenId) returns()
func (_Sacd *SacdSession) OnTransfer(asset common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _Sacd.Contract.OnTransfer(&_Sacd.TransactOpts, asset, tokenId)
}

// OnTransfer is a paid mutator transaction binding the contract method 0xe81e9b64.
//
// Solidity: function onTransfer(address asset, uint256 tokenId) returns()
func (_Sacd *SacdTransactorSession) OnTransfer(asset common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _Sacd.Contract.OnTransfer(&_Sacd.TransactOpts, asset, tokenId)
}

// SetPermissions is a paid mutator transaction binding the contract method 0xe711f339.
//
// Solidity: function setPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions, uint256 expiration, string source) returns()
func (_Sacd *SacdTransactor) SetPermissions(opts *bind.TransactOpts, asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int, expiration *big.Int, source string) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "setPermissions", asset, tokenId, grantee, permissions, expiration, source)
}

// SetPermissions is a paid mutator transaction binding the contract method 0xe711f339.
//
// Solidity: function setPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions, uint256 expiration, string source) returns()
func (_Sacd *SacdSession) SetPermissions(asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int, expiration *big.Int, source string) (*types.Transaction, error) {
	return _Sacd.Contract.SetPermissions(&_Sacd.TransactOpts, asset, tokenId, grantee, permissions, expiration, source)
}

// SetPermissions is a paid mutator transaction binding the contract method 0xe711f339.
//
// Solidity: function setPermissions(address asset, uint256 tokenId, address grantee, uint256 permissions, uint256 expiration, string source) returns()
func (_Sacd *SacdTransactorSession) SetPermissions(asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int, expiration *big.Int, source string) (*types.Transaction, error) {
	return _Sacd.Contract.SetPermissions(&_Sacd.TransactOpts, asset, tokenId, grantee, permissions, expiration, source)
}

// SacdPermissionsSetIterator is returned from FilterPermissionsSet and is used to iterate over the raw logs and unpacked data for PermissionsSet events raised by the Sacd contract.
type SacdPermissionsSetIterator struct {
	Event *SacdPermissionsSet // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SacdPermissionsSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SacdPermissionsSet)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SacdPermissionsSet)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SacdPermissionsSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SacdPermissionsSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SacdPermissionsSet represents a PermissionsSet event raised by the Sacd contract.
type SacdPermissionsSet struct {
	Asset       common.Address
	TokenId     *big.Int
	Permissions *big.Int
	Grantee     common.Address
	Expiration  *big.Int
	Source      string
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterPermissionsSet is a free log retrieval operation binding the contract event 0x948fe417941bab89f81888f9039015a1da93ff8cbe034f5615f7bf35679de7db.
//
// Solidity: event PermissionsSet(address indexed asset, uint256 indexed tokenId, uint256 permissions, address indexed grantee, uint256 expiration, string source)
func (_Sacd *SacdFilterer) FilterPermissionsSet(opts *bind.FilterOpts, asset []common.Address, tokenId []*big.Int, grantee []common.Address) (*SacdPermissionsSetIterator, error) {

	var assetRule []interface{}
	for _, assetItem := range asset {
		assetRule = append(assetRule, assetItem)
	}
	var tokenIdRule []interface{}
	for _, tokenIdItem := range tokenId {
		tokenIdRule = append(tokenIdRule, tokenIdItem)
	}

	var granteeRule []interface{}
	for _, granteeItem := range grantee {
		granteeRule = append(granteeRule, granteeItem)
	}

	logs, sub, err := _Sacd.contract.FilterLogs(opts, "PermissionsSet", assetRule, tokenIdRule, granteeRule)
	if err != nil {
		return nil, err
	}
	return &SacdPermissionsSetIterator{contract: _Sacd.contract, event: "PermissionsSet", logs: logs, sub: sub}, nil
}

// WatchPermissionsSet is a free log subscription operation binding the contract event 0x948fe417941bab89f81888f9039015a1da93ff8cbe034f5615f7bf35679de7db.
//
// Solidity: event PermissionsSet(address indexed asset, uint256 indexed tokenId, uint256 permissions, address indexed grantee, uint256 expiration, string source)
func (_Sacd *SacdFilterer) WatchPermissionsSet(opts *bind.WatchOpts, sink chan<- *SacdPermissionsSet, asset []common.Address, tokenId []*big.Int, grantee []common.Address) (event.Subscription, error) {

	var assetRule []interface{}
	for _, assetItem := range asset {
		assetRule = append(assetRule, assetItem)
	}
	var tokenIdRule []interface{}
	for _, tokenIdItem := range tokenId {
		tokenIdRule = append(tokenIdRule, tokenIdItem)
	}

	var granteeRule []interface{}
	for _, granteeItem := range grantee {
		granteeRule = append(granteeRule, granteeItem)
	}

	logs, sub, err := _Sacd.contract.WatchLogs(opts, "PermissionsSet", assetRule, tokenIdRule, granteeRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SacdPermissionsSet)
				if err := _Sacd.contract.UnpackLog(event, "PermissionsSet", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePermissionsSet is a log parse operation binding the contract event 0x948fe417941bab89f81888f9039015a1da93ff8cbe034f5615f7bf35679de7db.
//
// Solidity: event PermissionsSet(address indexed asset, uint256 indexed tokenId, uint256 permissions, address indexed grantee, uint256 expiration, string source)
func (_Sacd *SacdFilterer) ParsePermissionsSet(log types.Log) (*SacdPermissionsSet, error) {
	event := new(SacdPermissionsSet)
	if err := _Sacd.contract.UnpackLog(event, "PermissionsSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
