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
}

// SacdMetaData contains all meta data concerning the Sacd contract.
var SacdMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"AccessControlBadConfirmation\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"neededRole\",\"type\":\"bytes32\"}],\"name\":\"AccessControlUnauthorizedAccount\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"target\",\"type\":\"address\"}],\"name\":\"AddressEmptyCode\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"implementation\",\"type\":\"address\"}],\"name\":\"ERC1967InvalidImplementation\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ERC1967NonPayable\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"FailedInnerCall\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidInitialization\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"InvalidTokenId\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"NotInitializing\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"UUPSUnauthorizedCallContext\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"slot\",\"type\":\"bytes32\"}],\"name\":\"UUPSUnsupportedProxiableUUID\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"Unauthorized\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ZeroAddress\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"version\",\"type\":\"uint64\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"}],\"name\":\"PermissionsSet\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"previousAdminRole\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"newAdminRole\",\"type\":\"bytes32\"}],\"name\":\"RoleAdminChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"}],\"name\":\"RoleGranted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"}],\"name\":\"RoleRevoked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"implementation\",\"type\":\"address\"}],\"name\":\"Upgraded\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"DEFAULT_ADMIN_ROLE\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"UPGRADE_INTERFACE_VERSION\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"}],\"name\":\"currentPermissionRecord\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"}],\"internalType\":\"structISacd.PermissionRecord\",\"name\":\"permissionRecord\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"}],\"name\":\"getPermissions\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"}],\"name\":\"getRoleAdmin\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"grantRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint8\",\"name\":\"permissionIndex\",\"type\":\"uint8\"}],\"name\":\"hasPermission\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"}],\"name\":\"hasPermissions\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"hasRole\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"onTransfer\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"version\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"}],\"name\":\"permissionRecords\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"}],\"internalType\":\"structISacd.PermissionRecord\",\"name\":\"permissionRecord\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"proxiableUUID\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"callerConfirmation\",\"type\":\"address\"}],\"name\":\"renounceRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"revokeRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"grantee\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"expiration\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"}],\"name\":\"setPermissions\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes4\",\"name\":\"interfaceId\",\"type\":\"bytes4\"}],\"name\":\"supportsInterface\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"tokenId\",\"type\":\"uint256\"}],\"name\":\"tokenIdToVersion\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"version\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newImplementation\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"upgradeToAndCall\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"}]",
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

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_Sacd *SacdCaller) DEFAULTADMINROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "DEFAULT_ADMIN_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_Sacd *SacdSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _Sacd.Contract.DEFAULTADMINROLE(&_Sacd.CallOpts)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_Sacd *SacdCallerSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _Sacd.Contract.DEFAULTADMINROLE(&_Sacd.CallOpts)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_Sacd *SacdCaller) UPGRADEINTERFACEVERSION(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "UPGRADE_INTERFACE_VERSION")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_Sacd *SacdSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _Sacd.Contract.UPGRADEINTERFACEVERSION(&_Sacd.CallOpts)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_Sacd *SacdCallerSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _Sacd.Contract.UPGRADEINTERFACEVERSION(&_Sacd.CallOpts)
}

// CurrentPermissionRecord is a free data retrieval call binding the contract method 0x426d9e4a.
//
// Solidity: function currentPermissionRecord(address asset, uint256 tokenId, address grantee) view returns((uint256,uint256,string) permissionRecord)
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
// Solidity: function currentPermissionRecord(address asset, uint256 tokenId, address grantee) view returns((uint256,uint256,string) permissionRecord)
func (_Sacd *SacdSession) CurrentPermissionRecord(asset common.Address, tokenId *big.Int, grantee common.Address) (ISacdPermissionRecord, error) {
	return _Sacd.Contract.CurrentPermissionRecord(&_Sacd.CallOpts, asset, tokenId, grantee)
}

// CurrentPermissionRecord is a free data retrieval call binding the contract method 0x426d9e4a.
//
// Solidity: function currentPermissionRecord(address asset, uint256 tokenId, address grantee) view returns((uint256,uint256,string) permissionRecord)
func (_Sacd *SacdCallerSession) CurrentPermissionRecord(asset common.Address, tokenId *big.Int, grantee common.Address) (ISacdPermissionRecord, error) {
	return _Sacd.Contract.CurrentPermissionRecord(&_Sacd.CallOpts, asset, tokenId, grantee)
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

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_Sacd *SacdCaller) GetRoleAdmin(opts *bind.CallOpts, role [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "getRoleAdmin", role)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_Sacd *SacdSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _Sacd.Contract.GetRoleAdmin(&_Sacd.CallOpts, role)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_Sacd *SacdCallerSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _Sacd.Contract.GetRoleAdmin(&_Sacd.CallOpts, role)
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

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_Sacd *SacdCaller) HasRole(opts *bind.CallOpts, role [32]byte, account common.Address) (bool, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "hasRole", role, account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_Sacd *SacdSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _Sacd.Contract.HasRole(&_Sacd.CallOpts, role, account)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_Sacd *SacdCallerSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _Sacd.Contract.HasRole(&_Sacd.CallOpts, role, account)
}

// PermissionRecords is a free data retrieval call binding the contract method 0x15e7d96b.
//
// Solidity: function permissionRecords(address asset, uint256 tokenId, uint256 version, address grantee) view returns((uint256,uint256,string) permissionRecord)
func (_Sacd *SacdCaller) PermissionRecords(opts *bind.CallOpts, asset common.Address, tokenId *big.Int, version *big.Int, grantee common.Address) (ISacdPermissionRecord, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "permissionRecords", asset, tokenId, version, grantee)

	if err != nil {
		return *new(ISacdPermissionRecord), err
	}

	out0 := *abi.ConvertType(out[0], new(ISacdPermissionRecord)).(*ISacdPermissionRecord)

	return out0, err

}

// PermissionRecords is a free data retrieval call binding the contract method 0x15e7d96b.
//
// Solidity: function permissionRecords(address asset, uint256 tokenId, uint256 version, address grantee) view returns((uint256,uint256,string) permissionRecord)
func (_Sacd *SacdSession) PermissionRecords(asset common.Address, tokenId *big.Int, version *big.Int, grantee common.Address) (ISacdPermissionRecord, error) {
	return _Sacd.Contract.PermissionRecords(&_Sacd.CallOpts, asset, tokenId, version, grantee)
}

// PermissionRecords is a free data retrieval call binding the contract method 0x15e7d96b.
//
// Solidity: function permissionRecords(address asset, uint256 tokenId, uint256 version, address grantee) view returns((uint256,uint256,string) permissionRecord)
func (_Sacd *SacdCallerSession) PermissionRecords(asset common.Address, tokenId *big.Int, version *big.Int, grantee common.Address) (ISacdPermissionRecord, error) {
	return _Sacd.Contract.PermissionRecords(&_Sacd.CallOpts, asset, tokenId, version, grantee)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_Sacd *SacdCaller) ProxiableUUID(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "proxiableUUID")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_Sacd *SacdSession) ProxiableUUID() ([32]byte, error) {
	return _Sacd.Contract.ProxiableUUID(&_Sacd.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_Sacd *SacdCallerSession) ProxiableUUID() ([32]byte, error) {
	return _Sacd.Contract.ProxiableUUID(&_Sacd.CallOpts)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_Sacd *SacdCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _Sacd.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_Sacd *SacdSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _Sacd.Contract.SupportsInterface(&_Sacd.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_Sacd *SacdCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _Sacd.Contract.SupportsInterface(&_Sacd.CallOpts, interfaceId)
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

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_Sacd *SacdTransactor) GrantRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "grantRole", role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_Sacd *SacdSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Sacd.Contract.GrantRole(&_Sacd.TransactOpts, role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_Sacd *SacdTransactorSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Sacd.Contract.GrantRole(&_Sacd.TransactOpts, role, account)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Sacd *SacdTransactor) Initialize(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "initialize")
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Sacd *SacdSession) Initialize() (*types.Transaction, error) {
	return _Sacd.Contract.Initialize(&_Sacd.TransactOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Sacd *SacdTransactorSession) Initialize() (*types.Transaction, error) {
	return _Sacd.Contract.Initialize(&_Sacd.TransactOpts)
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

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_Sacd *SacdTransactor) RenounceRole(opts *bind.TransactOpts, role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "renounceRole", role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_Sacd *SacdSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _Sacd.Contract.RenounceRole(&_Sacd.TransactOpts, role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_Sacd *SacdTransactorSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _Sacd.Contract.RenounceRole(&_Sacd.TransactOpts, role, callerConfirmation)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_Sacd *SacdTransactor) RevokeRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "revokeRole", role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_Sacd *SacdSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Sacd.Contract.RevokeRole(&_Sacd.TransactOpts, role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_Sacd *SacdTransactorSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Sacd.Contract.RevokeRole(&_Sacd.TransactOpts, role, account)
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

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_Sacd *SacdTransactor) UpgradeToAndCall(opts *bind.TransactOpts, newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _Sacd.contract.Transact(opts, "upgradeToAndCall", newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_Sacd *SacdSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _Sacd.Contract.UpgradeToAndCall(&_Sacd.TransactOpts, newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_Sacd *SacdTransactorSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _Sacd.Contract.UpgradeToAndCall(&_Sacd.TransactOpts, newImplementation, data)
}

// SacdInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the Sacd contract.
type SacdInitializedIterator struct {
	Event *SacdInitialized // Event containing the contract specifics and raw log

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
func (it *SacdInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SacdInitialized)
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
		it.Event = new(SacdInitialized)
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
func (it *SacdInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SacdInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SacdInitialized represents a Initialized event raised by the Sacd contract.
type SacdInitialized struct {
	Version uint64
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_Sacd *SacdFilterer) FilterInitialized(opts *bind.FilterOpts) (*SacdInitializedIterator, error) {

	logs, sub, err := _Sacd.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &SacdInitializedIterator{contract: _Sacd.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_Sacd *SacdFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *SacdInitialized) (event.Subscription, error) {

	logs, sub, err := _Sacd.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SacdInitialized)
				if err := _Sacd.contract.UnpackLog(event, "Initialized", log); err != nil {
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

// ParseInitialized is a log parse operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_Sacd *SacdFilterer) ParseInitialized(log types.Log) (*SacdInitialized, error) {
	event := new(SacdInitialized)
	if err := _Sacd.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
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

// SacdRoleAdminChangedIterator is returned from FilterRoleAdminChanged and is used to iterate over the raw logs and unpacked data for RoleAdminChanged events raised by the Sacd contract.
type SacdRoleAdminChangedIterator struct {
	Event *SacdRoleAdminChanged // Event containing the contract specifics and raw log

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
func (it *SacdRoleAdminChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SacdRoleAdminChanged)
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
		it.Event = new(SacdRoleAdminChanged)
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
func (it *SacdRoleAdminChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SacdRoleAdminChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SacdRoleAdminChanged represents a RoleAdminChanged event raised by the Sacd contract.
type SacdRoleAdminChanged struct {
	Role              [32]byte
	PreviousAdminRole [32]byte
	NewAdminRole      [32]byte
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterRoleAdminChanged is a free log retrieval operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_Sacd *SacdFilterer) FilterRoleAdminChanged(opts *bind.FilterOpts, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (*SacdRoleAdminChangedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _Sacd.contract.FilterLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return &SacdRoleAdminChangedIterator{contract: _Sacd.contract, event: "RoleAdminChanged", logs: logs, sub: sub}, nil
}

// WatchRoleAdminChanged is a free log subscription operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_Sacd *SacdFilterer) WatchRoleAdminChanged(opts *bind.WatchOpts, sink chan<- *SacdRoleAdminChanged, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _Sacd.contract.WatchLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SacdRoleAdminChanged)
				if err := _Sacd.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
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

// ParseRoleAdminChanged is a log parse operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_Sacd *SacdFilterer) ParseRoleAdminChanged(log types.Log) (*SacdRoleAdminChanged, error) {
	event := new(SacdRoleAdminChanged)
	if err := _Sacd.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SacdRoleGrantedIterator is returned from FilterRoleGranted and is used to iterate over the raw logs and unpacked data for RoleGranted events raised by the Sacd contract.
type SacdRoleGrantedIterator struct {
	Event *SacdRoleGranted // Event containing the contract specifics and raw log

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
func (it *SacdRoleGrantedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SacdRoleGranted)
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
		it.Event = new(SacdRoleGranted)
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
func (it *SacdRoleGrantedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SacdRoleGrantedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SacdRoleGranted represents a RoleGranted event raised by the Sacd contract.
type SacdRoleGranted struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleGranted is a free log retrieval operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_Sacd *SacdFilterer) FilterRoleGranted(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*SacdRoleGrantedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _Sacd.contract.FilterLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &SacdRoleGrantedIterator{contract: _Sacd.contract, event: "RoleGranted", logs: logs, sub: sub}, nil
}

// WatchRoleGranted is a free log subscription operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_Sacd *SacdFilterer) WatchRoleGranted(opts *bind.WatchOpts, sink chan<- *SacdRoleGranted, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _Sacd.contract.WatchLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SacdRoleGranted)
				if err := _Sacd.contract.UnpackLog(event, "RoleGranted", log); err != nil {
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

// ParseRoleGranted is a log parse operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_Sacd *SacdFilterer) ParseRoleGranted(log types.Log) (*SacdRoleGranted, error) {
	event := new(SacdRoleGranted)
	if err := _Sacd.contract.UnpackLog(event, "RoleGranted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SacdRoleRevokedIterator is returned from FilterRoleRevoked and is used to iterate over the raw logs and unpacked data for RoleRevoked events raised by the Sacd contract.
type SacdRoleRevokedIterator struct {
	Event *SacdRoleRevoked // Event containing the contract specifics and raw log

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
func (it *SacdRoleRevokedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SacdRoleRevoked)
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
		it.Event = new(SacdRoleRevoked)
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
func (it *SacdRoleRevokedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SacdRoleRevokedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SacdRoleRevoked represents a RoleRevoked event raised by the Sacd contract.
type SacdRoleRevoked struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleRevoked is a free log retrieval operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_Sacd *SacdFilterer) FilterRoleRevoked(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*SacdRoleRevokedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _Sacd.contract.FilterLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &SacdRoleRevokedIterator{contract: _Sacd.contract, event: "RoleRevoked", logs: logs, sub: sub}, nil
}

// WatchRoleRevoked is a free log subscription operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_Sacd *SacdFilterer) WatchRoleRevoked(opts *bind.WatchOpts, sink chan<- *SacdRoleRevoked, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _Sacd.contract.WatchLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SacdRoleRevoked)
				if err := _Sacd.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
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

// ParseRoleRevoked is a log parse operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_Sacd *SacdFilterer) ParseRoleRevoked(log types.Log) (*SacdRoleRevoked, error) {
	event := new(SacdRoleRevoked)
	if err := _Sacd.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SacdUpgradedIterator is returned from FilterUpgraded and is used to iterate over the raw logs and unpacked data for Upgraded events raised by the Sacd contract.
type SacdUpgradedIterator struct {
	Event *SacdUpgraded // Event containing the contract specifics and raw log

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
func (it *SacdUpgradedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SacdUpgraded)
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
		it.Event = new(SacdUpgraded)
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
func (it *SacdUpgradedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SacdUpgradedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SacdUpgraded represents a Upgraded event raised by the Sacd contract.
type SacdUpgraded struct {
	Implementation common.Address
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterUpgraded is a free log retrieval operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_Sacd *SacdFilterer) FilterUpgraded(opts *bind.FilterOpts, implementation []common.Address) (*SacdUpgradedIterator, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _Sacd.contract.FilterLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return &SacdUpgradedIterator{contract: _Sacd.contract, event: "Upgraded", logs: logs, sub: sub}, nil
}

// WatchUpgraded is a free log subscription operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_Sacd *SacdFilterer) WatchUpgraded(opts *bind.WatchOpts, sink chan<- *SacdUpgraded, implementation []common.Address) (event.Subscription, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _Sacd.contract.WatchLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SacdUpgraded)
				if err := _Sacd.contract.UnpackLog(event, "Upgraded", log); err != nil {
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

// ParseUpgraded is a log parse operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_Sacd *SacdFilterer) ParseUpgraded(log types.Log) (*SacdUpgraded, error) {
	event := new(SacdUpgraded)
	if err := _Sacd.contract.UnpackLog(event, "Upgraded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
