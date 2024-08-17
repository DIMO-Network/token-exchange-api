// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package multiprivilege

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
)

// MultiprivilegeMetaData contains all meta data concerning the Multiprivilege contract.
var MultiprivilegeMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"privId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"expires\",\"type\":\"uint256\"}],\"name\":\"PrivilegeAssigned\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"privId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"expires\",\"type\":\"uint256\"}],\"name\":\"assignPrivilege\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"privId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"}],\"name\":\"hasPrivilege\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"privilegeEntry\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"privilegeRecord\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"enabled\",\"type\":\"bool\"},{\"internalType\":\"string\",\"name\":\"description\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"tokenIdToVersion\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// MultiprivilegeABI is the input ABI used to generate the binding from.
// Deprecated: Use MultiprivilegeMetaData.ABI instead.
var MultiprivilegeABI = MultiprivilegeMetaData.ABI

// Multiprivilege is an auto generated Go binding around an Ethereum contract.
type Multiprivilege struct {
	MultiprivilegeCaller     // Read-only binding to the contract
	MultiprivilegeTransactor // Write-only binding to the contract
	MultiprivilegeFilterer   // Log filterer for contract events
}

// MultiprivilegeCaller is an auto generated read-only Go binding around an Ethereum contract.
type MultiprivilegeCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MultiprivilegeTransactor is an auto generated write-only Go binding around an Ethereum contract.
type MultiprivilegeTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MultiprivilegeFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type MultiprivilegeFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MultiprivilegeSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type MultiprivilegeSession struct {
	Contract     *Multiprivilege   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// MultiprivilegeCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type MultiprivilegeCallerSession struct {
	Contract *MultiprivilegeCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// MultiprivilegeTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type MultiprivilegeTransactorSession struct {
	Contract     *MultiprivilegeTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// MultiprivilegeRaw is an auto generated low-level Go binding around an Ethereum contract.
type MultiprivilegeRaw struct {
	Contract *Multiprivilege // Generic contract binding to access the raw methods on
}

// MultiprivilegeCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type MultiprivilegeCallerRaw struct {
	Contract *MultiprivilegeCaller // Generic read-only contract binding to access the raw methods on
}

// MultiprivilegeTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type MultiprivilegeTransactorRaw struct {
	Contract *MultiprivilegeTransactor // Generic write-only contract binding to access the raw methods on
}

// NewMultiprivilege creates a new instance of Multiprivilege, bound to a specific deployed contract.
func NewMultiprivilege(address common.Address, backend bind.ContractBackend) (*Multiprivilege, error) {
	contract, err := bindMultiprivilege(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Multiprivilege{MultiprivilegeCaller: MultiprivilegeCaller{contract: contract}, MultiprivilegeTransactor: MultiprivilegeTransactor{contract: contract}, MultiprivilegeFilterer: MultiprivilegeFilterer{contract: contract}}, nil
}

// NewMultiprivilegeCaller creates a new read-only instance of Multiprivilege, bound to a specific deployed contract.
func NewMultiprivilegeCaller(address common.Address, caller bind.ContractCaller) (*MultiprivilegeCaller, error) {
	contract, err := bindMultiprivilege(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &MultiprivilegeCaller{contract: contract}, nil
}

// NewMultiprivilegeTransactor creates a new write-only instance of Multiprivilege, bound to a specific deployed contract.
func NewMultiprivilegeTransactor(address common.Address, transactor bind.ContractTransactor) (*MultiprivilegeTransactor, error) {
	contract, err := bindMultiprivilege(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &MultiprivilegeTransactor{contract: contract}, nil
}

// NewMultiprivilegeFilterer creates a new log filterer instance of Multiprivilege, bound to a specific deployed contract.
func NewMultiprivilegeFilterer(address common.Address, filterer bind.ContractFilterer) (*MultiprivilegeFilterer, error) {
	contract, err := bindMultiprivilege(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &MultiprivilegeFilterer{contract: contract}, nil
}

// bindMultiprivilege binds a generic wrapper to an already deployed contract.
func bindMultiprivilege(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(MultiprivilegeABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Multiprivilege *MultiprivilegeRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Multiprivilege.Contract.MultiprivilegeCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Multiprivilege *MultiprivilegeRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Multiprivilege.Contract.MultiprivilegeTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Multiprivilege *MultiprivilegeRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Multiprivilege.Contract.MultiprivilegeTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Multiprivilege *MultiprivilegeCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Multiprivilege.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Multiprivilege *MultiprivilegeTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Multiprivilege.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Multiprivilege *MultiprivilegeTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Multiprivilege.Contract.contract.Transact(opts, method, params...)
}

// HasPrivilege is a free data retrieval call binding the contract method 0x05d80b00.
//
// Solidity: function hasPrivilege(uint256 tokenId, uint256 privId, address user) view returns(bool)
func (_Multiprivilege *MultiprivilegeCaller) HasPrivilege(opts *bind.CallOpts, tokenId *big.Int, privId *big.Int, user common.Address) (bool, error) {
	var out []interface{}
	err := _Multiprivilege.contract.Call(opts, &out, "hasPrivilege", tokenId, privId, user)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasPrivilege is a free data retrieval call binding the contract method 0x05d80b00.
//
// Solidity: function hasPrivilege(uint256 tokenId, uint256 privId, address user) view returns(bool)
func (_Multiprivilege *MultiprivilegeSession) HasPrivilege(tokenId *big.Int, privId *big.Int, user common.Address) (bool, error) {
	return _Multiprivilege.Contract.HasPrivilege(&_Multiprivilege.CallOpts, tokenId, privId, user)
}

// HasPrivilege is a free data retrieval call binding the contract method 0x05d80b00.
//
// Solidity: function hasPrivilege(uint256 tokenId, uint256 privId, address user) view returns(bool)
func (_Multiprivilege *MultiprivilegeCallerSession) HasPrivilege(tokenId *big.Int, privId *big.Int, user common.Address) (bool, error) {
	return _Multiprivilege.Contract.HasPrivilege(&_Multiprivilege.CallOpts, tokenId, privId, user)
}

// PrivilegeEntry is a free data retrieval call binding the contract method 0x48db4640.
//
// Solidity: function privilegeEntry(uint256 , uint256 , uint256 , address ) view returns(uint256)
func (_Multiprivilege *MultiprivilegeCaller) PrivilegeEntry(opts *bind.CallOpts, arg0 *big.Int, arg1 *big.Int, arg2 *big.Int, arg3 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Multiprivilege.contract.Call(opts, &out, "privilegeEntry", arg0, arg1, arg2, arg3)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// PrivilegeEntry is a free data retrieval call binding the contract method 0x48db4640.
//
// Solidity: function privilegeEntry(uint256 , uint256 , uint256 , address ) view returns(uint256)
func (_Multiprivilege *MultiprivilegeSession) PrivilegeEntry(arg0 *big.Int, arg1 *big.Int, arg2 *big.Int, arg3 common.Address) (*big.Int, error) {
	return _Multiprivilege.Contract.PrivilegeEntry(&_Multiprivilege.CallOpts, arg0, arg1, arg2, arg3)
}

// PrivilegeEntry is a free data retrieval call binding the contract method 0x48db4640.
//
// Solidity: function privilegeEntry(uint256 , uint256 , uint256 , address ) view returns(uint256)
func (_Multiprivilege *MultiprivilegeCallerSession) PrivilegeEntry(arg0 *big.Int, arg1 *big.Int, arg2 *big.Int, arg3 common.Address) (*big.Int, error) {
	return _Multiprivilege.Contract.PrivilegeEntry(&_Multiprivilege.CallOpts, arg0, arg1, arg2, arg3)
}

// PrivilegeRecord is a free data retrieval call binding the contract method 0xf9ad3efe.
//
// Solidity: function privilegeRecord(uint256 ) view returns(bool enabled, string description)
func (_Multiprivilege *MultiprivilegeCaller) PrivilegeRecord(opts *bind.CallOpts, arg0 *big.Int) (struct {
	Enabled     bool
	Description string
}, error) {
	var out []interface{}
	err := _Multiprivilege.contract.Call(opts, &out, "privilegeRecord", arg0)

	outstruct := new(struct {
		Enabled     bool
		Description string
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Enabled = *abi.ConvertType(out[0], new(bool)).(*bool)
	outstruct.Description = *abi.ConvertType(out[1], new(string)).(*string)

	return *outstruct, err

}

// PrivilegeRecord is a free data retrieval call binding the contract method 0xf9ad3efe.
//
// Solidity: function privilegeRecord(uint256 ) view returns(bool enabled, string description)
func (_Multiprivilege *MultiprivilegeSession) PrivilegeRecord(arg0 *big.Int) (struct {
	Enabled     bool
	Description string
}, error) {
	return _Multiprivilege.Contract.PrivilegeRecord(&_Multiprivilege.CallOpts, arg0)
}

// PrivilegeRecord is a free data retrieval call binding the contract method 0xf9ad3efe.
//
// Solidity: function privilegeRecord(uint256 ) view returns(bool enabled, string description)
func (_Multiprivilege *MultiprivilegeCallerSession) PrivilegeRecord(arg0 *big.Int) (struct {
	Enabled     bool
	Description string
}, error) {
	return _Multiprivilege.Contract.PrivilegeRecord(&_Multiprivilege.CallOpts, arg0)
}

// TokenIdToVersion is a free data retrieval call binding the contract method 0xf1a9d41c.
//
// Solidity: function tokenIdToVersion(uint256 ) view returns(uint256)
func (_Multiprivilege *MultiprivilegeCaller) TokenIdToVersion(opts *bind.CallOpts, arg0 *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Multiprivilege.contract.Call(opts, &out, "tokenIdToVersion", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TokenIdToVersion is a free data retrieval call binding the contract method 0xf1a9d41c.
//
// Solidity: function tokenIdToVersion(uint256 ) view returns(uint256)
func (_Multiprivilege *MultiprivilegeSession) TokenIdToVersion(arg0 *big.Int) (*big.Int, error) {
	return _Multiprivilege.Contract.TokenIdToVersion(&_Multiprivilege.CallOpts, arg0)
}

// TokenIdToVersion is a free data retrieval call binding the contract method 0xf1a9d41c.
//
// Solidity: function tokenIdToVersion(uint256 ) view returns(uint256)
func (_Multiprivilege *MultiprivilegeCallerSession) TokenIdToVersion(arg0 *big.Int) (*big.Int, error) {
	return _Multiprivilege.Contract.TokenIdToVersion(&_Multiprivilege.CallOpts, arg0)
}

// AssignPrivilege is a paid mutator transaction binding the contract method 0xa87b256a.
//
// Solidity: function assignPrivilege(uint256 tokenId, uint256 privId, address user, uint256 expires) returns()
func (_Multiprivilege *MultiprivilegeTransactor) AssignPrivilege(opts *bind.TransactOpts, tokenId *big.Int, privId *big.Int, user common.Address, expires *big.Int) (*types.Transaction, error) {
	return _Multiprivilege.contract.Transact(opts, "assignPrivilege", tokenId, privId, user, expires)
}

// AssignPrivilege is a paid mutator transaction binding the contract method 0xa87b256a.
//
// Solidity: function assignPrivilege(uint256 tokenId, uint256 privId, address user, uint256 expires) returns()
func (_Multiprivilege *MultiprivilegeSession) AssignPrivilege(tokenId *big.Int, privId *big.Int, user common.Address, expires *big.Int) (*types.Transaction, error) {
	return _Multiprivilege.Contract.AssignPrivilege(&_Multiprivilege.TransactOpts, tokenId, privId, user, expires)
}

// AssignPrivilege is a paid mutator transaction binding the contract method 0xa87b256a.
//
// Solidity: function assignPrivilege(uint256 tokenId, uint256 privId, address user, uint256 expires) returns()
func (_Multiprivilege *MultiprivilegeTransactorSession) AssignPrivilege(tokenId *big.Int, privId *big.Int, user common.Address, expires *big.Int) (*types.Transaction, error) {
	return _Multiprivilege.Contract.AssignPrivilege(&_Multiprivilege.TransactOpts, tokenId, privId, user, expires)
}

// MultiprivilegePrivilegeAssignedIterator is returned from FilterPrivilegeAssigned and is used to iterate over the raw logs and unpacked data for PrivilegeAssigned events raised by the Multiprivilege contract.
type MultiprivilegePrivilegeAssignedIterator struct {
	Event *MultiprivilegePrivilegeAssigned // Event containing the contract specifics and raw log

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
func (it *MultiprivilegePrivilegeAssignedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(MultiprivilegePrivilegeAssigned)
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
		it.Event = new(MultiprivilegePrivilegeAssigned)
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
func (it *MultiprivilegePrivilegeAssignedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *MultiprivilegePrivilegeAssignedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// MultiprivilegePrivilegeAssigned represents a PrivilegeAssigned event raised by the Multiprivilege contract.
type MultiprivilegePrivilegeAssigned struct {
	TokenId *big.Int
	PrivId  *big.Int
	User    common.Address
	Expires *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPrivilegeAssigned is a free log retrieval operation binding the contract event 0x00ec38d8c28ef03d08af2b7530ba918d5a692f49a4537f44a942c56b164881ad.
//
// Solidity: event PrivilegeAssigned(uint256 tokenId, uint256 privId, address indexed user, uint256 expires)
func (_Multiprivilege *MultiprivilegeFilterer) FilterPrivilegeAssigned(opts *bind.FilterOpts, user []common.Address) (*MultiprivilegePrivilegeAssignedIterator, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}

	logs, sub, err := _Multiprivilege.contract.FilterLogs(opts, "PrivilegeAssigned", userRule)
	if err != nil {
		return nil, err
	}
	return &MultiprivilegePrivilegeAssignedIterator{contract: _Multiprivilege.contract, event: "PrivilegeAssigned", logs: logs, sub: sub}, nil
}

// WatchPrivilegeAssigned is a free log subscription operation binding the contract event 0x00ec38d8c28ef03d08af2b7530ba918d5a692f49a4537f44a942c56b164881ad.
//
// Solidity: event PrivilegeAssigned(uint256 tokenId, uint256 privId, address indexed user, uint256 expires)
func (_Multiprivilege *MultiprivilegeFilterer) WatchPrivilegeAssigned(opts *bind.WatchOpts, sink chan<- *MultiprivilegePrivilegeAssigned, user []common.Address) (event.Subscription, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}

	logs, sub, err := _Multiprivilege.contract.WatchLogs(opts, "PrivilegeAssigned", userRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(MultiprivilegePrivilegeAssigned)
				if err := _Multiprivilege.contract.UnpackLog(event, "PrivilegeAssigned", log); err != nil {
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

// ParsePrivilegeAssigned is a log parse operation binding the contract event 0x00ec38d8c28ef03d08af2b7530ba918d5a692f49a4537f44a942c56b164881ad.
//
// Solidity: event PrivilegeAssigned(uint256 tokenId, uint256 privId, address indexed user, uint256 expires)
func (_Multiprivilege *MultiprivilegeFilterer) ParsePrivilegeAssigned(log types.Log) (*MultiprivilegePrivilegeAssigned, error) {
	event := new(MultiprivilegePrivilegeAssigned)
	if err := _Multiprivilege.contract.UnpackLog(event, "PrivilegeAssigned", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
