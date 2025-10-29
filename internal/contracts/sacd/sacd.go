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

// ISacdPermissionRecord is an auto generated low-level Go binding around an user-defined struct.
type ISacdPermissionRecord struct {
	Permissions *big.Int
	Expiration  *big.Int
	Source      string
	TemplateId  *big.Int
}

// SacdMetaData contains all meta data concerning the Sacd contract.
var SacdMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"}],\"name\":\"currentPermissionRecord\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"templateId\",\"type\":\"uint256\"}],\"internalType\":\"structISacd.PermissionRecord\",\"name\":\"permissionRecord\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"}],\"name\":\"getPermissions\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"grantor\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"}],\"name\":\"getAccountPermissions\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"grantor\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"}],\"name\":\"accountPermissionRecords\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"templateId\",\"type\":\"uint256\"}],\"internalType\":\"structISacd.PermissionRecord\",\"name\":\"permissionRecord\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
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

// AccountPermissionRecords is a free data retrieval call binding the contract method 0x30eaba75.
//
// Solidity: function accountPermissionRecords(address grantor, address grantee) view returns((uint256,uint256,string,uint256) permissionRecord)
func (_Sacd *SacdCaller) AccountPermissionRecords(opts *bind.CallOpts, grantor common.Address, grantee common.Address) (ISacdPermissionRecord, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "accountPermissionRecords", grantor, grantee)

	if err != nil {
		return *new(ISacdPermissionRecord), err
	}

	out0 := *abi.ConvertType(out[0], new(ISacdPermissionRecord)).(*ISacdPermissionRecord)

	return out0, err

}

// AccountPermissionRecords is a free data retrieval call binding the contract method 0x30eaba75.
//
// Solidity: function accountPermissionRecords(address grantor, address grantee) view returns((uint256,uint256,string,uint256) permissionRecord)
func (_Sacd *SacdSession) AccountPermissionRecords(grantor common.Address, grantee common.Address) (ISacdPermissionRecord, error) {
	return _Sacd.Contract.AccountPermissionRecords(&_Sacd.CallOpts, grantor, grantee)
}

// AccountPermissionRecords is a free data retrieval call binding the contract method 0x30eaba75.
//
// Solidity: function accountPermissionRecords(address grantor, address grantee) view returns((uint256,uint256,string,uint256) permissionRecord)
func (_Sacd *SacdCallerSession) AccountPermissionRecords(grantor common.Address, grantee common.Address) (ISacdPermissionRecord, error) {
	return _Sacd.Contract.AccountPermissionRecords(&_Sacd.CallOpts, grantor, grantee)
}

// CurrentPermissionRecord is a free data retrieval call binding the contract method 0x426d9e4a.
//
// Solidity: function currentPermissionRecord(address asset, uint256 tokenId, address grantee) view returns((uint256,uint256,string,uint256) permissionRecord)
func (_Sacd *SacdCaller) CurrentPermissionRecord(opts *bind.CallOpts, asset common.Address, tokenId *big.Int, grantee common.Address) (ISacdPermissionRecord, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "currentPermissionRecord", asset, tokenId, grantee)

	if err != nil {
		return *new(ISacdPermissionRecord), err
	}

	out0 := *abi.ConvertType(out[0], new(ISacdPermissionRecord)).(*ISacdPermissionRecord)

	return out0, err

}

// CurrentPermissionRecord is a free data retrieval call binding the contract method 0x426d9e4a.
//
// Solidity: function currentPermissionRecord(address asset, uint256 tokenId, address grantee) view returns((uint256,uint256,string,uint256) permissionRecord)
func (_Sacd *SacdSession) CurrentPermissionRecord(asset common.Address, tokenId *big.Int, grantee common.Address) (ISacdPermissionRecord, error) {
	return _Sacd.Contract.CurrentPermissionRecord(&_Sacd.CallOpts, asset, tokenId, grantee)
}

// CurrentPermissionRecord is a free data retrieval call binding the contract method 0x426d9e4a.
//
// Solidity: function currentPermissionRecord(address asset, uint256 tokenId, address grantee) view returns((uint256,uint256,string,uint256) permissionRecord)
func (_Sacd *SacdCallerSession) CurrentPermissionRecord(asset common.Address, tokenId *big.Int, grantee common.Address) (ISacdPermissionRecord, error) {
	return _Sacd.Contract.CurrentPermissionRecord(&_Sacd.CallOpts, asset, tokenId, grantee)
}

// GetAccountPermissions is a free data retrieval call binding the contract method 0x6805e547.
//
// Solidity: function getAccountPermissions(address grantor, address grantee, uint256 permissions) view returns(uint256)
func (_Sacd *SacdCaller) GetAccountPermissions(opts *bind.CallOpts, grantor common.Address, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "getAccountPermissions", grantor, grantee, permissions)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetAccountPermissions is a free data retrieval call binding the contract method 0x6805e547.
//
// Solidity: function getAccountPermissions(address grantor, address grantee, uint256 permissions) view returns(uint256)
func (_Sacd *SacdSession) GetAccountPermissions(grantor common.Address, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	return _Sacd.Contract.GetAccountPermissions(&_Sacd.CallOpts, grantor, grantee, permissions)
}

// GetAccountPermissions is a free data retrieval call binding the contract method 0x6805e547.
//
// Solidity: function getAccountPermissions(address grantor, address grantee, uint256 permissions) view returns(uint256)
func (_Sacd *SacdCallerSession) GetAccountPermissions(grantor common.Address, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	return _Sacd.Contract.GetAccountPermissions(&_Sacd.CallOpts, grantor, grantee, permissions)
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
