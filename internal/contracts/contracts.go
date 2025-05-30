package contracts

import (
	"math/big"

	priv "github.com/DIMO-Network/token-exchange-api/internal/contracts/multi_privilege"
	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

//go:generate mockgen -source contracts.go -destination mocks/contracts_manager_mock.go
type Manager interface {
	GetMultiPrivilege(nftAddress string, client bind.ContractBackend) (MultiPriv, error)
	GetSacd(sacdAddress string, client bind.ContractBackend) (Sacd, error)
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

func (cm *contractsManager) GetSacd(sacdAddress string, client bind.ContractBackend) (Sacd, error) {
	scAdr := common.HexToAddress(sacdAddress)

	sd, err := sacd.NewSacd(scAdr, client)
	if err != nil {
		return nil, err
	}

	return sd, nil
}

// MultiPriv this is done for mocking purposes
type MultiPriv interface {
	HasPrivilege(opts *bind.CallOpts, tokenID *big.Int, privID *big.Int, user common.Address) (bool, error)
}

type Sacd interface {
	CurrentPermissionRecord(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address) (sacd.ISacdPermissionRecord, error)
	GetPermissions(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error)
}
