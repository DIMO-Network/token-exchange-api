// Package docs GENERATED BY SWAG; DO NOT EDIT
// This file was generated by swaggo/swag at
// 2023-01-17 16:34:51.169942 -0500 EST m=+1.164618293
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
                            "$ref": "#/definitions/internal_controllers.PermissionTokenRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/internal_controllers.PermissionTokenResponse"
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
            "type": "object"
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
            "type": "object"
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
