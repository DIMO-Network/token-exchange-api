package api

import "github.com/rs/zerolog"

func NewVehicleTokenExchangeService(logger *zerolog.Logger) *VehicleTokenExchangeService {
	return &VehicleTokenExchangeService{logger: logger}
}

type VehicleTokenExchangeService struct {
	logger *zerolog.Logger
}
