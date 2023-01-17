// Package docs GENERATED BY SWAG; DO NOT EDIT
// This file was generated by swaggo/swag at
// 2023-01-17 16:11:40.172407 -0500 EST m=+1.087952543
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/tokens/exchange": {
            "post": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "Returns a signed token with the requested privileges.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "privileges on the correct token.",
                "parameters": [
                    {
                        "description": "Requested privileges: must include address, token id, and privilege ids",
                        "name": "tokenRequest",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/github_com_DIMO-Network_token-exchange-api_internal_controllers.PermissionTokenRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/github_com_DIMO-Network_token-exchange-api_internal_controllers.PermissionTokenResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "big.Int": {
            "type": "object"
        },
        "github_com_DIMO-Network_token-exchange-api_internal_controllers.PermissionTokenRequest": {
            "type": "object",
            "required": [
                "nftContractAddress",
                "tokenId"
            ],
            "properties": {
                "nftContractAddress": {
                    "description": "NFTContractAddress is the address of the NFT contract. Privileges will be checked\non-chain at this address.",
                    "type": "string"
                },
                "privileges": {
                    "description": "Privileges is a list of the desired privileges. It must not be empty.",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/big.Int"
                    }
                },
                "tokenId": {
                    "description": "TokenID is the NFT token id.",
                    "allOf": [
                        {
                            "$ref": "#/definitions/big.Int"
                        }
                    ]
                }
            }
        },
        "github_com_DIMO-Network_token-exchange-api_internal_controllers.PermissionTokenResponse": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string"
                }
            }
        },
        "internal_controllers.PermissionTokenRequest": {
            "type": "object",
            "required": [
                "nftContractAddress",
                "tokenId"
            ],
            "properties": {
                "nftContractAddress": {
                    "description": "NFTContractAddress is the address of the NFT contract. Privileges will be checked\non-chain at this address.",
                    "type": "string"
                },
                "privileges": {
                    "description": "Privileges is a list of the desired privileges. It must not be empty.",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/big.Int"
                    }
                },
                "tokenId": {
                    "description": "TokenID is the NFT token id.",
                    "allOf": [
                        {
                            "$ref": "#/definitions/big.Int"
                        }
                    ]
                }
            }
        },
        "internal_controllers.PermissionTokenResponse": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string"
                }
            }
        }
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "/v1",
	Schemes:          []string{},
	Title:            "DIMO Token Exchange API",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}