package contracts

import (
	priv "github.com/DIMO-Network/token-exchange-api/internal/contracts/multi_privilege"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

//go:generate mockgen -source main.go -destination mocks/contracts_manager_mock.go
type ContractsManager interface {
	GetMultiPrivilege(nftAddress string, client bind.ContractBackend) (*priv.Multiprivilege, error)
}

type contractsManager struct {
}

func NewContractsManager() ContractsManager {
	return &contractsManager{}
}

func (cm *contractsManager) GetMultiPrivilege(nftAddress string, client bind.ContractBackend) (*priv.Multiprivilege, error) {
	mpAdr := common.HexToAddress(nftAddress)

	mp, err := priv.NewMultiprivilege(mpAdr, client)
	if err != nil {
		return nil, err
	}

	return mp, nil
}
