package contracts

import (
	"math/big"

	priv "github.com/DIMO-Network/token-exchange-api/internal/contracts/multi_privilege"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

//go:generate mockgen -source main.go -destination mocks/contracts_manager_mock.go
type Manager interface {
	GetMultiPrivilege(nftAddress string, client bind.ContractBackend) (MultiPriv, error)
}

type contractsManager struct {
}

func NewContractsManager() Manager {
	return &contractsManager{}
}

func (cm *contractsManager) GetMultiPrivilege(nftAddress string, client bind.ContractBackend) (MultiPriv, error) {
	mpAdr := common.HexToAddress(nftAddress)

	mp, err := priv.NewMultiprivilege(mpAdr, client)
	if err != nil {
		return nil, err
	}

	return mp, nil
}

// MultiPriv this is done for mocking purposes
type MultiPriv interface {
	HasPrivilege(opts *bind.CallOpts, tokenID *big.Int, privID *big.Int, user common.Address) (bool, error)
}
