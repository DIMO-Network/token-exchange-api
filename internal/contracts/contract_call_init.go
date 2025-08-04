package contracts

import "github.com/ethereum/go-ethereum/ethclient"

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
