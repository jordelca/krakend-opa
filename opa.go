package opa

import (
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
const Namespace = "github_com/jordelca/krakend-opa"

func HandlerFactory(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return OpaValidator(hf, logger)
}

func OpaValidator(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		handler := hf(cfg, prxy)
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
					input.role = "admin"
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
			fmt.Println("method", c.Request.Method)
			fmt.Println("value:", rs[0].Expressions[0].Value)

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
