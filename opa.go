package opa

import (
	"errors"
	"math/rand"
	"net/http"

	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	ginkrakend "github.com/devopsfaith/krakend/router/gin"
	"github.com/gin-gonic/gin"
)

// Namespace is the key to look for extra configuration details
const Namespace = "github_com/jordelca/krakend-opa"

func HandlerFactory(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	logger.Info("OPA: HandlerFactory")
	return OpaValidator(hf, logger)
}

func OpaValidator(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		handler := hf(cfg, prxy)
		logger.Info("OPA: validator enabled for the endpoint")

		return func(c *gin.Context) {
			if rand.Int()%2 == 0 {
				logger.Info("OPA: Unauthorized")
				c.AbortWithError(http.StatusUnauthorized, errors.New("error"))
				return
			}

			logger.Info("OPA: Authorized")
			handler(c)
		}
	}
}
