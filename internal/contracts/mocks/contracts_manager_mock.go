// Code generated by MockGen. DO NOT EDIT.
// Source: main.go
//
// Generated by this command:
//
//	mockgen -source main.go -destination mocks/contracts_manager_mock.go
//
// Package mock_contracts is a generated GoMock package.
package mock_contracts

import (
	big "math/big"
	reflect "reflect"

	contracts "github.com/DIMO-Network/token-exchange-api/internal/contracts"
	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"
	common "github.com/ethereum/go-ethereum/common"
	gomock "go.uber.org/mock/gomock"
)

// MockContractsManager is a mock of ContractsManager interface.
type MockContractsManager struct {
	ctrl     *gomock.Controller
	recorder *MockContractsManagerMockRecorder
}

// MockContractsManagerMockRecorder is the mock recorder for MockContractsManager.
type MockContractsManagerMockRecorder struct {
	mock *MockContractsManager
}

// NewMockContractsManager creates a new mock instance.
func NewMockContractsManager(ctrl *gomock.Controller) *MockContractsManager {
	mock := &MockContractsManager{ctrl: ctrl}
	mock.recorder = &MockContractsManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockContractsManager) EXPECT() *MockContractsManagerMockRecorder {
	return m.recorder
}

// GetMultiPrivilege mocks base method.
func (m *MockContractsManager) GetMultiPrivilege(nftAddress string, client bind.ContractBackend) (contracts.MultiPriv, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMultiPrivilege", nftAddress, client)
	ret0, _ := ret[0].(contracts.MultiPriv)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMultiPrivilege indicates an expected call of GetMultiPrivilege.
func (mr *MockContractsManagerMockRecorder) GetMultiPrivilege(nftAddress, client any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMultiPrivilege", reflect.TypeOf((*MockContractsManager)(nil).GetMultiPrivilege), nftAddress, client)
}

// MockMultiPriv is a mock of MultiPriv interface.
type MockMultiPriv struct {
	ctrl     *gomock.Controller
	recorder *MockMultiPrivMockRecorder
}

// MockMultiPrivMockRecorder is the mock recorder for MockMultiPriv.
type MockMultiPrivMockRecorder struct {
	mock *MockMultiPriv
}

// NewMockMultiPriv creates a new mock instance.
func NewMockMultiPriv(ctrl *gomock.Controller) *MockMultiPriv {
	mock := &MockMultiPriv{ctrl: ctrl}
	mock.recorder = &MockMultiPrivMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMultiPriv) EXPECT() *MockMultiPrivMockRecorder {
	return m.recorder
}

// HasPrivilege mocks base method.
func (m *MockMultiPriv) HasPrivilege(opts *bind.CallOpts, tokenId, privId *big.Int, user common.Address) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HasPrivilege", opts, tokenId, privId, user)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HasPrivilege indicates an expected call of HasPrivilege.
func (mr *MockMultiPrivMockRecorder) HasPrivilege(opts, tokenId, privId, user any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HasPrivilege", reflect.TypeOf((*MockMultiPriv)(nil).HasPrivilege), opts, tokenId, privId, user)
}