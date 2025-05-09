// Code generated by MockGen. DO NOT EDIT.
// Source: contract_call_init.go
//
// Generated by this command:
//
//	mockgen -source contract_call_init.go -destination mocks/contract_call_init_mock.go
//

// Package mock_contracts is a generated GoMock package.
package mock_contracts

import (
	reflect "reflect"

	ethclient "github.com/ethereum/go-ethereum/ethclient"
	gomock "go.uber.org/mock/gomock"
)

// MockContractCallInitializer is a mock of ContractCallInitializer interface.
type MockContractCallInitializer struct {
	ctrl     *gomock.Controller
	recorder *MockContractCallInitializerMockRecorder
	isgomock struct{}
}

// MockContractCallInitializerMockRecorder is the mock recorder for MockContractCallInitializer.
type MockContractCallInitializerMockRecorder struct {
	mock *MockContractCallInitializer
}

// NewMockContractCallInitializer creates a new mock instance.
func NewMockContractCallInitializer(ctrl *gomock.Controller) *MockContractCallInitializer {
	mock := &MockContractCallInitializer{ctrl: ctrl}
	mock.recorder = &MockContractCallInitializerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockContractCallInitializer) EXPECT() *MockContractCallInitializerMockRecorder {
	return m.recorder
}

// InitContractCall mocks base method.
func (m *MockContractCallInitializer) InitContractCall(nodeURL string) (*ethclient.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitContractCall", nodeURL)
	ret0, _ := ret[0].(*ethclient.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InitContractCall indicates an expected call of InitContractCall.
func (mr *MockContractCallInitializerMockRecorder) InitContractCall(nodeURL any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitContractCall", reflect.TypeOf((*MockContractCallInitializer)(nil).InitContractCall), nodeURL)
}
