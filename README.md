# Go Palo Alto Prisma Cloud library  [![Build Status](https://github.com/paskal/go-prisma/actions/workflows/ci-test.yml/badge.svg)](https://github.com/paskal/go-prisma/actions) [![Go Report Card](https://goreportcard.com/badge/github.com/paskal/go-prisma)](https://goreportcard.com/report/github.com/paskal/go-prisma)[![Coverage Status](https://coveralls.io/repos/github/paskal/go-prisma/badge.svg?branch=master)](https://coveralls.io/github/paskal/go-prisma?branch=master)[![GoDoc](https://godoc.org/github.com/paskal/go-prisma?status.svg)](https://pkg.go.dev/github.com/paskal/go-prisma?tab=doc)

Tiny library for [Prisma Cloud API](https://api.docs.prismacloud.io/reference) access.

It takes care of authorization and token renewal, and let you concentrate on issuing requests.

## How to install

```console
go get github.com/paskal/go-prisma
```

## Usage example

```go
package main

import (
	"log"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/paskal/go-prisma"
)

func main() {
	var opts struct {
		PrismAPIUrl      string `long:"prisma_api_url" default:"https://api.eu.prismacloud.io" description:"Prisma API URL"`
		PrismAPIKey      string `long:"prisma_api_key" required:"true" description:"Prisma API key"`
		PrismAPIPassword string `long:"prisma_api_password" required:"true" description:"Prisma API password"`
	}
	if _, err := flags.Parse(&opts); err != nil {
		os.Exit(1)
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("[INFO] Initialising Prisma connection with API key %s", opts.PrismAPIKey)

	p := prisma.NewClient(opts.PrismAPIKey, opts.PrismAPIPassword, opts.PrismAPIUrl)
	healthCheckResult, err := p.Call("GET", "/check", nil)
	if err != nil {
		log.Printf("[ERROR] Can't check Prisma health, %s", err)
		return
	}
	log.Printf("[INFO] Prisma /check endpoint answer: %s", healthCheckResult)
}
```
