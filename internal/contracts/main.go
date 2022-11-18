package contracts

import (
	m "github.com/DIMO-Network/token-exchange-service/internal/contracts/multi_priviledge"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type ContractsManager struct {
	MultiPriviledge *m.Multiprivilege
}

type ContractsAddressBook struct {
	MultiPriviledgeAddress string
}

func NewContractsManager(addrs ContractsAddressBook, client bind.ContractBackend) (*ContractsManager, error) {
	mpAdr := common.HexToAddress(addrs.MultiPriviledgeAddress)

	mp, err := m.NewMultiprivilege(mpAdr, client)
	if err != nil {
		return &ContractsManager{}, err
	}

	return &ContractsManager{
		MultiPriviledge: mp,
	}, nil
}
