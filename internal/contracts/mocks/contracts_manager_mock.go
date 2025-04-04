// Code generated by MockGen. DO NOT EDIT.
// Source: contracts.go
//
// Generated by this command:
//
//	mockgen -source contracts.go -destination mocks/contracts_manager_mock.go
//

// Package mock_contracts is a generated GoMock package.
package mock_contracts

import (
	big "math/big"
	reflect "reflect"

	contracts "github.com/DIMO-Network/token-exchange-api/internal/contracts"
	sacd "github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"
	common "github.com/ethereum/go-ethereum/common"
	gomock "go.uber.org/mock/gomock"
)

// MockManager is a mock of Manager interface.
type MockManager struct {
	ctrl     *gomock.Controller
	recorder *MockManagerMockRecorder
	isgomock struct{}
}

// MockManagerMockRecorder is the mock recorder for MockManager.
type MockManagerMockRecorder struct {
	mock *MockManager
}

// NewMockManager creates a new mock instance.
func NewMockManager(ctrl *gomock.Controller) *MockManager {
	mock := &MockManager{ctrl: ctrl}
	mock.recorder = &MockManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManager) EXPECT() *MockManagerMockRecorder {
	return m.recorder
}

// GetMultiPrivilege mocks base method.
func (m *MockManager) GetMultiPrivilege(nftAddress string, client bind.ContractBackend) (contracts.MultiPriv, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMultiPrivilege", nftAddress, client)
	ret0, _ := ret[0].(contracts.MultiPriv)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMultiPrivilege indicates an expected call of GetMultiPrivilege.
func (mr *MockManagerMockRecorder) GetMultiPrivilege(nftAddress, client any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMultiPrivilege", reflect.TypeOf((*MockManager)(nil).GetMultiPrivilege), nftAddress, client)
}

// GetSacd mocks base method.
func (m *MockManager) GetSacd(sacdAddress string, client bind.ContractBackend) (contracts.Sacd, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSacd", sacdAddress, client)
	ret0, _ := ret[0].(contracts.Sacd)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSacd indicates an expected call of GetSacd.
func (mr *MockManagerMockRecorder) GetSacd(sacdAddress, client any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSacd", reflect.TypeOf((*MockManager)(nil).GetSacd), sacdAddress, client)
}

// MockMultiPriv is a mock of MultiPriv interface.
type MockMultiPriv struct {
	ctrl     *gomock.Controller
	recorder *MockMultiPrivMockRecorder
	isgomock struct{}
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
func (m *MockMultiPriv) HasPrivilege(opts *bind.CallOpts, tokenID, privID *big.Int, user common.Address) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HasPrivilege", opts, tokenID, privID, user)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HasPrivilege indicates an expected call of HasPrivilege.
func (mr *MockMultiPrivMockRecorder) HasPrivilege(opts, tokenID, privID, user any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HasPrivilege", reflect.TypeOf((*MockMultiPriv)(nil).HasPrivilege), opts, tokenID, privID, user)
}

// MockSacd is a mock of Sacd interface.
type MockSacd struct {
	ctrl     *gomock.Controller
	recorder *MockSacdMockRecorder
	isgomock struct{}
}

// MockSacdMockRecorder is the mock recorder for MockSacd.
type MockSacdMockRecorder struct {
	mock *MockSacd
}

// NewMockSacd creates a new mock instance.
func NewMockSacd(ctrl *gomock.Controller) *MockSacd {
	mock := &MockSacd{ctrl: ctrl}
	mock.recorder = &MockSacdMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSacd) EXPECT() *MockSacdMockRecorder {
	return m.recorder
}

// CurrentPermissionRecord mocks base method.
func (m *MockSacd) CurrentPermissionRecord(opts *bind.CallOpts, asset common.Address, tokenId *big.Int, grantee common.Address) (sacd.ISacdPermissionRecord, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CurrentPermissionRecord", opts, asset, tokenId, grantee)
	ret0, _ := ret[0].(sacd.ISacdPermissionRecord)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CurrentPermissionRecord indicates an expected call of CurrentPermissionRecord.
func (mr *MockSacdMockRecorder) CurrentPermissionRecord(opts, asset, tokenId, grantee any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CurrentPermissionRecord", reflect.TypeOf((*MockSacd)(nil).CurrentPermissionRecord), opts, asset, tokenId, grantee)
}

// GetPermissions mocks base method.
func (m *MockSacd) GetPermissions(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPermissions", opts, asset, tokenID, grantee, permissions)
	ret0, _ := ret[0].(*big.Int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPermissions indicates an expected call of GetPermissions.
func (mr *MockSacdMockRecorder) GetPermissions(opts, asset, tokenID, grantee, permissions any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPermissions", reflect.TypeOf((*MockSacd)(nil).GetPermissions), opts, asset, tokenID, grantee, permissions)
}
