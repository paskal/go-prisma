# Go Palo Alto Prisma Cloud library  [![Build Status](https://github.com/paskal/go-prisma/workflows/test/badge.svg)](https://github.com/paskal/go-prisma/actions) [![Go Report Card](https://goreportcard.com/badge/github.com/paskal/go-prisma)](https://goreportcard.com/report/github.com/paskal/go-prisma)

Tiny library for [Prisma Cloud API](https://api.docs.prismacloud.io/reference) access. 

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

type opts struct {
	PrismAPIUrl      string `long:"prisma_api_url" env:"PRISMA_API_URL" default:"https://api.eu.prismacloud.io" description:"Prisma API URL"`
	PrismAPIKey      string `long:"prisma_api_key" env:"PRISMA_API_KEY" required:"true" description:"Prisma API key"`
	PrismAPIPassword string `long:"prisma_api_password" env:"PRISMA_API_PASSWORD" required:"true" description:"Prisma API password"`
}

func main() {
	var opts = opts{}
	if _, err := flags.Parse(&opts); err != nil {
		os.Exit(1)
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("[INFO] Initialising Prisma connection with API key %s", opts.PrismAPIKey)


	p := Prisma{Username: opts.PrismAPIKey, Password: opts.PrismAPIPassword, APIUrl: opts.PrismAPIUrl}
	healthCheckResult, err := p.DoAPIRequest("GET", "/check", nil)
	if err != nil {
		log.Printf("[ERROR] Can't check Prisma health, %v", err)
	}
	log.Printf("[INFO] Prisma /check endpoint answer: %s", healthCheckResult)
}
```
