package opa

import (
	"io"
	"log"

	"github.com/devopsfaith/krakend/config"
)

// Namespace is the key to look for extra configuration details
const Namespace = "github_com/jordelca/krakend-opa"

// NewLogger returns a krakend logger wrapping a gologging logger
func NewLogger(cfg config.ExtraConfig, ws ...io.Writer) {
	log.Println("Hello world!")
}
