// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package devlicenseaccount

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

// DevLicenseAccountMetaData contains all meta data concerning the DevLicenseAccount contract.
var DevLicenseAccountMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"signer\",\"type\":\"address\"}],\"name\":\"isSigner\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// DevLicenseAccountABI is the input ABI used to generate the binding from.
// Deprecated: Use DevLicenseAccountMetaData.ABI instead.
var DevLicenseAccountABI = DevLicenseAccountMetaData.ABI

// DevLicenseAccount is an auto generated Go binding around an Ethereum contract.
type DevLicenseAccount struct {
	DevLicenseAccountCaller     // Read-only binding to the contract
	DevLicenseAccountTransactor // Write-only binding to the contract
	DevLicenseAccountFilterer   // Log filterer for contract events
}

// DevLicenseAccountCaller is an auto generated read-only Go binding around an Ethereum contract.
type DevLicenseAccountCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DevLicenseAccountTransactor is an auto generated write-only Go binding around an Ethereum contract.
type DevLicenseAccountTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DevLicenseAccountFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type DevLicenseAccountFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DevLicenseAccountSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type DevLicenseAccountSession struct {
	Contract     *DevLicenseAccount // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// DevLicenseAccountCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type DevLicenseAccountCallerSession struct {
	Contract *DevLicenseAccountCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// DevLicenseAccountTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type DevLicenseAccountTransactorSession struct {
	Contract     *DevLicenseAccountTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// DevLicenseAccountRaw is an auto generated low-level Go binding around an Ethereum contract.
type DevLicenseAccountRaw struct {
	Contract *DevLicenseAccount // Generic contract binding to access the raw methods on
}

// DevLicenseAccountCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type DevLicenseAccountCallerRaw struct {
	Contract *DevLicenseAccountCaller // Generic read-only contract binding to access the raw methods on
}

// DevLicenseAccountTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type DevLicenseAccountTransactorRaw struct {
	Contract *DevLicenseAccountTransactor // Generic write-only contract binding to access the raw methods on
}

// NewDevLicenseAccount creates a new instance of DevLicenseAccount, bound to a specific deployed contract.
func NewDevLicenseAccount(address common.Address, backend bind.ContractBackend) (*DevLicenseAccount, error) {
	contract, err := bindDevLicenseAccount(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &DevLicenseAccount{DevLicenseAccountCaller: DevLicenseAccountCaller{contract: contract}, DevLicenseAccountTransactor: DevLicenseAccountTransactor{contract: contract}, DevLicenseAccountFilterer: DevLicenseAccountFilterer{contract: contract}}, nil
}

// NewDevLicenseAccountCaller creates a new read-only instance of DevLicenseAccount, bound to a specific deployed contract.
func NewDevLicenseAccountCaller(address common.Address, caller bind.ContractCaller) (*DevLicenseAccountCaller, error) {
	contract, err := bindDevLicenseAccount(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &DevLicenseAccountCaller{contract: contract}, nil
}

// NewDevLicenseAccountTransactor creates a new write-only instance of DevLicenseAccount, bound to a specific deployed contract.
func NewDevLicenseAccountTransactor(address common.Address, transactor bind.ContractTransactor) (*DevLicenseAccountTransactor, error) {
	contract, err := bindDevLicenseAccount(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &DevLicenseAccountTransactor{contract: contract}, nil
}

// NewDevLicenseAccountFilterer creates a new log filterer instance of DevLicenseAccount, bound to a specific deployed contract.
func NewDevLicenseAccountFilterer(address common.Address, filterer bind.ContractFilterer) (*DevLicenseAccountFilterer, error) {
	contract, err := bindDevLicenseAccount(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &DevLicenseAccountFilterer{contract: contract}, nil
}

// bindDevLicenseAccount binds a generic wrapper to an already deployed contract.
func bindDevLicenseAccount(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := DevLicenseAccountMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DevLicenseAccount *DevLicenseAccountRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DevLicenseAccount.Contract.DevLicenseAccountCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DevLicenseAccount *DevLicenseAccountRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DevLicenseAccount.Contract.DevLicenseAccountTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DevLicenseAccount *DevLicenseAccountRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DevLicenseAccount.Contract.DevLicenseAccountTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DevLicenseAccount *DevLicenseAccountCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DevLicenseAccount.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DevLicenseAccount *DevLicenseAccountTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DevLicenseAccount.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DevLicenseAccount *DevLicenseAccountTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DevLicenseAccount.Contract.contract.Transact(opts, method, params...)
}

// IsSigner is a free data retrieval call binding the contract method 0x7df73e27.
//
// Solidity: function isSigner(address signer) view returns(bool)
func (_DevLicenseAccount *DevLicenseAccountCaller) IsSigner(opts *bind.CallOpts, signer common.Address) (bool, error) {
	var out []interface{}
	err := _DevLicenseAccount.contract.Call(opts, &out, "isSigner", signer)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsSigner is a free data retrieval call binding the contract method 0x7df73e27.
//
// Solidity: function isSigner(address signer) view returns(bool)
func (_DevLicenseAccount *DevLicenseAccountSession) IsSigner(signer common.Address) (bool, error) {
	return _DevLicenseAccount.Contract.IsSigner(&_DevLicenseAccount.CallOpts, signer)
}

// IsSigner is a free data retrieval call binding the contract method 0x7df73e27.
//
// Solidity: function isSigner(address signer) view returns(bool)
func (_DevLicenseAccount *DevLicenseAccountCallerSession) IsSigner(signer common.Address) (bool, error) {
	return _DevLicenseAccount.Contract.IsSigner(&_DevLicenseAccount.CallOpts, signer)
}
