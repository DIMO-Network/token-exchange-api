// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contracts

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
	ABI: "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_sacdTemplate\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"ERC1167FailedCreateClone\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"InvalidTokenId\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"Unauthorized\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sacd\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"SacdCreated\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"createSacd\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"sacd\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"}],\"name\":\"createSacd\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"sacd\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint8\",\"name\":\"permissionIndex\",\"type\":\"uint8\"}],\"name\":\"hasPermission\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"}],\"name\":\"hasPermissions\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"onTransfer\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"sacdTemplate\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"sacds\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"sacd\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
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

// SacdTemplate is a free data retrieval call binding the contract method 0x794a7dc0.
//
// Solidity: function sacdTemplate() view returns(address)
func (_Sacd *SacdCaller) SacdTemplate(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "sacdTemplate")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// SacdTemplate is a free data retrieval call binding the contract method 0x794a7dc0.
//
// Solidity: function sacdTemplate() view returns(address)
func (_Sacd *SacdSession) SacdTemplate() (common.Address, error) {
	return _Sacd.Contract.SacdTemplate(&_Sacd.CallOpts)
}

// SacdTemplate is a free data retrieval call binding the contract method 0x794a7dc0.
//
// Solidity: function sacdTemplate() view returns(address)
func (_Sacd *SacdCallerSession) SacdTemplate() (common.Address, error) {
	return _Sacd.Contract.SacdTemplate(&_Sacd.CallOpts)
}

// Sacds is a free data retrieval call binding the contract method 0x65cb60ee.
//
// Solidity: function sacds(address asset, uint256 tokenId) view returns(address sacd)
func (_Sacd *SacdCaller) Sacds(opts *bind.CallOpts, asset common.Address, tokenId *big.Int) (common.Address, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "sacds", asset, tokenId)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Sacds is a free data retrieval call binding the contract method 0x65cb60ee.
//
// Solidity: function sacds(address asset, uint256 tokenId) view returns(address sacd)
func (_Sacd *SacdSession) Sacds(asset common.Address, tokenId *big.Int) (common.Address, error) {
	return _Sacd.Contract.Sacds(&_Sacd.CallOpts, asset, tokenId)
}

// Sacds is a free data retrieval call binding the contract method 0x65cb60ee.
//
// Solidity: function sacds(address asset, uint256 tokenId) view returns(address sacd)
func (_Sacd *SacdCallerSession) Sacds(asset common.Address, tokenId *big.Int) (common.Address, error) {
	return _Sacd.Contract.Sacds(&_Sacd.CallOpts, asset, tokenId)
}

// CreateSacd is a paid mutator transaction binding the contract method 0x29daf0bc.
//
// Solidity: function createSacd(address asset, uint256 tokenId) returns(address sacd)
func (_Sacd *SacdTransactor) CreateSacd(opts *bind.TransactOpts, asset common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "createSacd", asset, tokenId)
}

// CreateSacd is a paid mutator transaction binding the contract method 0x29daf0bc.
//
// Solidity: function createSacd(address asset, uint256 tokenId) returns(address sacd)
func (_Sacd *SacdSession) CreateSacd(asset common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _Sacd.Contract.CreateSacd(&_Sacd.TransactOpts, asset, tokenId)
}

// CreateSacd is a paid mutator transaction binding the contract method 0x29daf0bc.
//
// Solidity: function createSacd(address asset, uint256 tokenId) returns(address sacd)
func (_Sacd *SacdTransactorSession) CreateSacd(asset common.Address, tokenId *big.Int) (*types.Transaction, error) {
	return _Sacd.Contract.CreateSacd(&_Sacd.TransactOpts, asset, tokenId)
}

// CreateSacd0 is a paid mutator transaction binding the contract method 0x4fbdd199.
//
// Solidity: function createSacd(address asset, uint256 tokenId, address grantee, uint256 permissions, uint256 expiration, string source) returns(address sacd)
func (_Sacd *SacdTransactor) CreateSacd0(opts *bind.TransactOpts, asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int, expiration *big.Int, source string) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "createSacd0", asset, tokenId, grantee, permissions, expiration, source)
}

// CreateSacd0 is a paid mutator transaction binding the contract method 0x4fbdd199.
//
// Solidity: function createSacd(address asset, uint256 tokenId, address grantee, uint256 permissions, uint256 expiration, string source) returns(address sacd)
func (_Sacd *SacdSession) CreateSacd0(asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int, expiration *big.Int, source string) (*types.Transaction, error) {
	return _Sacd.Contract.CreateSacd0(&_Sacd.TransactOpts, asset, tokenId, grantee, permissions, expiration, source)
}

// CreateSacd0 is a paid mutator transaction binding the contract method 0x4fbdd199.
//
// Solidity: function createSacd(address asset, uint256 tokenId, address grantee, uint256 permissions, uint256 expiration, string source) returns(address sacd)
func (_Sacd *SacdTransactorSession) CreateSacd0(asset common.Address, tokenId *big.Int, grantee common.Address, permissions *big.Int, expiration *big.Int, source string) (*types.Transaction, error) {
	return _Sacd.Contract.CreateSacd0(&_Sacd.TransactOpts, asset, tokenId, grantee, permissions, expiration, source)
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

// SacdSacdCreatedIterator is returned from FilterSacdCreated and is used to iterate over the raw logs and unpacked data for SacdCreated events raised by the Sacd contract.
type SacdSacdCreatedIterator struct {
	Event *SacdSacdCreated // Event containing the contract specifics and raw log

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
func (it *SacdSacdCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SacdSacdCreated)
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
		it.Event = new(SacdSacdCreated)
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
func (it *SacdSacdCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SacdSacdCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SacdSacdCreated represents a SacdCreated event raised by the Sacd contract.
type SacdSacdCreated struct {
	Sacd    common.Address
	Asset   common.Address
	TokenId *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterSacdCreated is a free log retrieval operation binding the contract event 0x041313a76158b9a9ea3a4f6312744b931caaaf999992d20d23d44f27fa93f382.
//
// Solidity: event SacdCreated(address indexed sacd, address indexed asset, uint256 indexed tokenId)
func (_Sacd *SacdFilterer) FilterSacdCreated(opts *bind.FilterOpts, sacd []common.Address, asset []common.Address, tokenId []*big.Int) (*SacdSacdCreatedIterator, error) {

	var sacdRule []interface{}
	for _, sacdItem := range sacd {
		sacdRule = append(sacdRule, sacdItem)
	}
	var assetRule []interface{}
	for _, assetItem := range asset {
		assetRule = append(assetRule, assetItem)
	}
	var tokenIdRule []interface{}
	for _, tokenIdItem := range tokenId {
		tokenIdRule = append(tokenIdRule, tokenIdItem)
	}

	logs, sub, err := _Sacd.contract.FilterLogs(opts, "SacdCreated", sacdRule, assetRule, tokenIdRule)
	if err != nil {
		return nil, err
	}
	return &SacdSacdCreatedIterator{contract: _Sacd.contract, event: "SacdCreated", logs: logs, sub: sub}, nil
}

// WatchSacdCreated is a free log subscription operation binding the contract event 0x041313a76158b9a9ea3a4f6312744b931caaaf999992d20d23d44f27fa93f382.
//
// Solidity: event SacdCreated(address indexed sacd, address indexed asset, uint256 indexed tokenId)
func (_Sacd *SacdFilterer) WatchSacdCreated(opts *bind.WatchOpts, sink chan<- *SacdSacdCreated, sacd []common.Address, asset []common.Address, tokenId []*big.Int) (event.Subscription, error) {

	var sacdRule []interface{}
	for _, sacdItem := range sacd {
		sacdRule = append(sacdRule, sacdItem)
	}
	var assetRule []interface{}
	for _, assetItem := range asset {
		assetRule = append(assetRule, assetItem)
	}
	var tokenIdRule []interface{}
	for _, tokenIdItem := range tokenId {
		tokenIdRule = append(tokenIdRule, tokenIdItem)
	}

	logs, sub, err := _Sacd.contract.WatchLogs(opts, "SacdCreated", sacdRule, assetRule, tokenIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SacdSacdCreated)
				if err := _Sacd.contract.UnpackLog(event, "SacdCreated", log); err != nil {
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

// ParseSacdCreated is a log parse operation binding the contract event 0x041313a76158b9a9ea3a4f6312744b931caaaf999992d20d23d44f27fa93f382.
//
// Solidity: event SacdCreated(address indexed sacd, address indexed asset, uint256 indexed tokenId)
func (_Sacd *SacdFilterer) ParseSacdCreated(log types.Log) (*SacdSacdCreated, error) {
	event := new(SacdSacdCreated)
	if err := _Sacd.contract.UnpackLog(event, "SacdCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
