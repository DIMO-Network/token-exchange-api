// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package template

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

// ITemplateTemplateData is an auto generated low-level Go binding around an user-defined struct.
type ITemplateTemplateData struct {
	Asset       common.Address
	Permissions *big.Int
	Source      string
	IsActive    bool
}

// TemplateMetaData contains all meta data concerning the Template contract.
var TemplateMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"templateId\",\"type\":\"uint256\"}],\"name\":\"templates\",\"outputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"permissions\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"source\",\"type\":\"string\"},{\"internalType\":\"bool\",\"name\":\"isActive\",\"type\":\"bool\"}],\"internalType\":\"structITemplate.TemplateData\",\"name\":\"templateData\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// TemplateABI is the input ABI used to generate the binding from.
// Deprecated: Use TemplateMetaData.ABI instead.
var TemplateABI = TemplateMetaData.ABI

// Template is an auto generated Go binding around an Ethereum contract.
type Template struct {
	TemplateCaller     // Read-only binding to the contract
	TemplateTransactor // Write-only binding to the contract
	TemplateFilterer   // Log filterer for contract events
}

// TemplateCaller is an auto generated read-only Go binding around an Ethereum contract.
type TemplateCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TemplateTransactor is an auto generated write-only Go binding around an Ethereum contract.
type TemplateTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TemplateFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type TemplateFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TemplateSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type TemplateSession struct {
	Contract     *Template         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// TemplateCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type TemplateCallerSession struct {
	Contract *TemplateCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// TemplateTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type TemplateTransactorSession struct {
	Contract     *TemplateTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// TemplateRaw is an auto generated low-level Go binding around an Ethereum contract.
type TemplateRaw struct {
	Contract *Template // Generic contract binding to access the raw methods on
}

// TemplateCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type TemplateCallerRaw struct {
	Contract *TemplateCaller // Generic read-only contract binding to access the raw methods on
}

// TemplateTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type TemplateTransactorRaw struct {
	Contract *TemplateTransactor // Generic write-only contract binding to access the raw methods on
}

// NewTemplate creates a new instance of Template, bound to a specific deployed contract.
func NewTemplate(address common.Address, backend bind.ContractBackend) (*Template, error) {
	contract, err := bindTemplate(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Template{TemplateCaller: TemplateCaller{contract: contract}, TemplateTransactor: TemplateTransactor{contract: contract}, TemplateFilterer: TemplateFilterer{contract: contract}}, nil
}

// NewTemplateCaller creates a new read-only instance of Template, bound to a specific deployed contract.
func NewTemplateCaller(address common.Address, caller bind.ContractCaller) (*TemplateCaller, error) {
	contract, err := bindTemplate(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &TemplateCaller{contract: contract}, nil
}

// NewTemplateTransactor creates a new write-only instance of Template, bound to a specific deployed contract.
func NewTemplateTransactor(address common.Address, transactor bind.ContractTransactor) (*TemplateTransactor, error) {
	contract, err := bindTemplate(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &TemplateTransactor{contract: contract}, nil
}

// NewTemplateFilterer creates a new log filterer instance of Template, bound to a specific deployed contract.
func NewTemplateFilterer(address common.Address, filterer bind.ContractFilterer) (*TemplateFilterer, error) {
	contract, err := bindTemplate(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &TemplateFilterer{contract: contract}, nil
}

// bindTemplate binds a generic wrapper to an already deployed contract.
func bindTemplate(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := TemplateMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Template *TemplateRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Template.Contract.TemplateCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Template *TemplateRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Template.Contract.TemplateTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Template *TemplateRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Template.Contract.TemplateTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Template *TemplateCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Template.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Template *TemplateTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Template.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Template *TemplateTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Template.Contract.contract.Transact(opts, method, params...)
}

// Templates is a free data retrieval call binding the contract method 0xbc525652.
//
// Solidity: function templates(uint256 templateId) view returns((address,uint256,string,bool) templateData)
func (_Template *TemplateCaller) Templates(opts *bind.CallOpts, templateId *big.Int) (ITemplateTemplateData, error) {
	var out []interface{}
	err := _Template.contract.Call(opts, &out, "templates", templateId)

	if err != nil {
		return *new(ITemplateTemplateData), err
	}

	out0 := *abi.ConvertType(out[0], new(ITemplateTemplateData)).(*ITemplateTemplateData)

	return out0, err

}

// Templates is a free data retrieval call binding the contract method 0xbc525652.
//
// Solidity: function templates(uint256 templateId) view returns((address,uint256,string,bool) templateData)
func (_Template *TemplateSession) Templates(templateId *big.Int) (ITemplateTemplateData, error) {
	return _Template.Contract.Templates(&_Template.CallOpts, templateId)
}

// Templates is a free data retrieval call binding the contract method 0xbc525652.
//
// Solidity: function templates(uint256 templateId) view returns((address,uint256,string,bool) templateData)
func (_Template *TemplateCallerSession) Templates(templateId *big.Int) (ITemplateTemplateData, error) {
	return _Template.Contract.Templates(&_Template.CallOpts, templateId)
}
