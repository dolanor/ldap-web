package main

import (
	"os"
	"strconv"
)

type config struct {
	ldapHost           string
	ldapPort           int
	basedn             string
	dnTemplate         string
	userFilterTemplate string
}

func loadCfg() *config {
	ldapPortStr := os.Getenv("LDAPWEB_PORT")
	ldapPort, err := strconv.Atoi(ldapPortStr)
	if err != nil {
		panic("bad LDAP port configured")
	}
	return &config{
		ldapHost:           os.Getenv("LDAPWEB_HOST"),
		ldapPort:           ldapPort,
		basedn:             os.Getenv("LDAPWEB_BASEDN"),
		dnTemplate:         os.Getenv("LDAPWEB_DN_TEMPLATE"),
		userFilterTemplate: os.Getenv("LDAPWEB_USERFILTER_TEMPLATE"),
	}
}
