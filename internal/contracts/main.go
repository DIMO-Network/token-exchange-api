package contracts

import (
	priv "github.com/DIMO-Network/token-exchange-api/internal/contracts/multi_privilege"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type ContractsManager struct {
	MultiPrivilege *priv.Multiprivilege
}

type ContractsAddressBook struct {
	MultiPrivilegeAddress string
}

func NewContractsManager(addrs ContractsAddressBook, client bind.ContractBackend) (*ContractsManager, error) {
	mpAdr := common.HexToAddress(addrs.MultiPrivilegeAddress)

	mp, err := priv.NewMultiprivilege(mpAdr, client)
	if err != nil {
		return nil, err
	}

	return &ContractsManager{
		MultiPrivilege: mp,
	}, nil
}

func InitContractCall(nodeUrl, contractAddress string) (*ethclient.Client, ContractsAddressBook, error) {
	client, err := ethclient.Dial(nodeUrl)
	if err != nil {
		return nil, ContractsAddressBook{}, err
	}
	cadr := ContractsAddressBook{
		MultiPrivilegeAddress: contractAddress,
	}

	return client, cadr, nil
}
