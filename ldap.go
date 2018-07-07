package main

import (
	"fmt"

	"gopkg.in/ldap.v2"
)

// getBaseDN construct the baseDN out of the baseDNTemplate containing %s
// that would be replaced by username
func getBaseDN(dnTemplate, username string) string {
	return fmt.Sprintf(dnTemplate, username)
}

func ldapChangePassword(cfg *config, username, userdn, password, newpassword string) error {
	c, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", cfg.ldapHost, cfg.ldapPort))
	if err != nil {
		return err
	}
	defer c.Close()

	err = c.Bind(userdn, password)
	if err != nil {
		return err
	}

	pwdModify := ldap.NewPasswordModifyRequest(userdn, password, newpassword)

	_, err = c.PasswordModify(pwdModify)
	if err != nil {
		return err
	}
	return nil
}

func ldapAddMailalias(cfg *config, username, userdn, password, newmailalias string) error {
	c, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", cfg.ldapHost, cfg.ldapPort))
	if err != nil {
		return err
	}
	defer c.Close()

	err = c.Bind(userdn, password)
	if err != nil {
		return err
	}

	maMod := ldap.NewModifyRequest(userdn)
	maMod.Add("mailalias", []string{newmailalias})

	err = c.Modify(maMod)
	if err != nil {
		return err
	}
	return nil
}

func ldapSearch(cfg *config, username, userdn, password string) (*ldap.SearchResult, error) {
	c, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", cfg.ldapHost, cfg.ldapPort))
	if err != nil {
		return nil, err
	}
	defer c.Close()

	err = c.Bind(userdn, password)
	if err != nil {
		return nil, err
	}

	searchReq := ldap.NewSearchRequest(cfg.basedn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(cfg.userFilterTemplate, username),
		[]string{},
		nil,
	)

	srch, err := c.Search(searchReq)
	if err != nil {
		return nil, err
	}
	return srch, nil
}
