package opa

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	ginkrakend "github.com/devopsfaith/krakend/router/gin"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// Namespace is the key to look for extra configuration details
const Namespace = "github.com/jordelca/krakend-opa"

type Config struct {
	Host string
	Port int
}

var (
	ErrNoValidatorCfg = errors.New("OPA: no validator config")
)

func HandlerFactory(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return OpaValidator(hf, logger)
}

func OpaValidator(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		handler := hf(cfg, prxy)
		scfg, err := GetConfig(cfg)

		if err == ErrNoValidatorCfg {
			logger.Info("OPA: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}

		logger.Info("OPA: Host", scfg.Host)
		logger.Info("OPA: Port", scfg.Port)

		logger.Info("OPA: validator enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			receivedToken := strings.TrimPrefix(c.Request.Header.Get("Authorization"), "Bearer ")

			parsedToken, err := jwt.Parse(receivedToken, nil)
			if err != nil || parsedToken == nil {
				fmt.Println("token is invalid: ", err)
			}

			claims := parsedToken.Claims.(jwt.MapClaims)

			// Define a simple policy.
			module := `
				package example

				default allow = false
				
				allow {
					input.role == "admin"
				}
			`

			// Compile the module. The keys are used as identifiers in error messages.
			compiler, _ := ast.CompileModules(map[string]string{
				"example.rego": module,
			})

			// Create a new query that uses the compiled policy from above.
			rego := rego.New(
				rego.Query("data.example.allow"),
				rego.Compiler(compiler),
				rego.Input(
					map[string]interface{}{
						"role":   claims["role"],
						"method": c.Request.Method,
						"token":  receivedToken,
					},
				),
			)

			// Run evaluation.
			rs, err := rego.Eval(c)

			if err != nil {
				// Handle error.
				logger.Info("OPA: Error")
			}

			// Inspect results.
			fmt.Println("len:", len(rs))
			fmt.Println("user", c.Param("user"))
			fmt.Println("bearer", c.Request.Header.Get("Authorization"))

			if rs[0].Expressions[0].Value == false {
				logger.Info("OPA: Unauthorized")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid role"})
				c.Abort()
				return
			}

			logger.Info("OPA: Authorized")
			handler(c)
		}
	}
}

func GetConfig(cfg *config.EndpointConfig) (*Config, error) {
	v, ok := cfg.ExtraConfig[Namespace]
	if !ok {
		return nil, ErrNoValidatorCfg
	}
	tmp, ok := v.(map[string]interface{})
	if !ok {
		return nil, ErrNoValidatorCfg
	}
	config := new(Config)
	if v, ok := tmp["host"]; ok {
		if name, ok := v.(string); ok {
			config.Host = name
		}
	}
	if v, ok := tmp["port"]; ok {
		switch i := v.(type) {
		case int:
			config.Port = i
		case float64:
			config.Port = int(i)
		}
	}

	return config, nil
}
