package contracts

import (
	priv "github.com/DIMO-Network/token-exchange-service/internal/contracts/multi_privilege"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
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
		return &ContractsManager{}, err
	}

	return &ContractsManager{
		MultiPrivilege: mp,
	}, nil
}
