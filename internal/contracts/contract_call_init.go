package contracts

import "github.com/ethereum/go-ethereum/ethclient"

//go:generate mockgen -source contract_call_init.go -destination mocks/contract_call_init_mock.go
type ContractCallInitializer interface {
	InitContractCall(nodeURL string) (*ethclient.Client, error)
}

type contractCallInitializer struct {
}

func NewContractsCallInitializer() ContractCallInitializer {
	return &contractCallInitializer{}
}

func (cc *contractCallInitializer) InitContractCall(nodeURL string) (*ethclient.Client, error) {
	client, err := ethclient.Dial(nodeURL)
	if err != nil {
		return nil, err
	}

	return client, nil
}
