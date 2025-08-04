package contracts

import (
	"math/big"

	"github.com/DIMO-Network/token-exchange-api/internal/contracts/sacd"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type Manager interface {
	GetSacd(sacdAddress string, client bind.ContractBackend) (Sacd, error)
}

type contractsManager struct {
}

func NewContractsManager() Manager {
	return &contractsManager{}
}

func (cm *contractsManager) GetSacd(sacdAddress string, client bind.ContractBackend) (Sacd, error) {
	scAdr := common.HexToAddress(sacdAddress)

	sd, err := sacd.NewSacd(scAdr, client)
	if err != nil {
		return nil, err
	}

	return sd, nil
}

type Sacd interface {
	CurrentPermissionRecord(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address) (sacd.ISacdPermissionRecord, error)
	GetPermissions(opts *bind.CallOpts, asset common.Address, tokenID *big.Int, grantee common.Address, permissions *big.Int) (*big.Int, error)
}
