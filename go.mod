module github.com/DIMO-Network/token-exchange-api

go 1.24.0

toolchain go1.24.1

replace github.com/dexidp/dex/api/v2 => github.com/DIMO-Network/dex/api/v2 v2.0.1-0.20240402140037-3b70843c1bed

require (
	github.com/DIMO-Network/shared v0.12.10
	github.com/dexidp/dex/api/v2 v2.35.3
	github.com/ethereum/go-ethereum v1.15.7
	github.com/gofiber/fiber/v2 v2.52.6
	github.com/gofiber/swagger v1.0.0
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/pkg/errors v0.9.1
	github.com/rs/zerolog v1.32.0
	github.com/stretchr/testify v1.10.0
	github.com/swaggo/swag v1.16.3
	go.uber.org/mock v0.5.0
	google.golang.org/grpc v1.71.0
)

require golang.org/x/exp v0.0.0-20240213143201-ec583247a57a // indirect

require (
	github.com/DIMO-Network/yaml v0.1.0 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	golang.org/x/time v0.9.0 // indirect
)

require (
	github.com/DIMO-Network/cloudevent v0.0.4
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/MicahParks/keyfunc/v2 v2.1.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/avast/retry-go/v4 v4.5.1 // indirect
	github.com/aws/aws-sdk-go-v2 v1.32.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.28.1 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.17.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/consensys/bavard v0.1.22 // indirect
	github.com/consensys/gnark-crypto v0.14.0 // indirect
	github.com/crate-crypto/go-ipa v0.0.0-20240724233137-53bbb0ceb27a // indirect
	github.com/crate-crypto/go-kzg-4844 v1.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/deckarep/golang-set/v2 v2.6.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/ethereum/c-kzg-4844 v1.0.0 // indirect
	github.com/ethereum/go-verkle v0.2.2 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.20.2 // indirect
	github.com/go-openapi/jsonreference v0.20.4 // indirect
	github.com/go-openapi/spec v0.20.14 // indirect
	github.com/go-openapi/swag v0.22.9 // indirect
	github.com/gofiber/contrib/jwt v1.0.8
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.18.0
	github.com/prometheus/client_model v0.6.0 // indirect
	github.com/prometheus/common v0.47.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/supranational/blst v0.3.14 // indirect
	github.com/swaggo/files/v2 v2.0.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tklauser/go-sysconf v0.3.13 // indirect
	github.com/tklauser/numcpus v0.7.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.52.0
	github.com/valyala/tcplisten v1.0.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/net v0.36.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/tools v0.29.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
	google.golang.org/protobuf v1.36.4
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)
