package main

import (
	"fmt"
	"log"
	"net/http"
	"text/tabwriter"
)

func (lw *ldapWeb) displayUserInfo(w http.ResponseWriter, r *http.Request) {
	u, err := lw.getUserInfo(r)
	if err != nil {
		http.Error(w, "couldn't parse form: "+err.Error(), http.StatusInternalServerError)
		return
	}

	srch, err := ldapSearch(lw.config, u.username, u.userdn, u.password)
	if err != nil {
		http.Error(w, fmt.Sprintf("couldn't search LDAP: %+v\n", err), http.StatusInternalServerError)
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', tabwriter.AlignRight)
	for _, e := range srch.Entries {
		for _, attr := range e.Attributes {
			fmt.Fprintf(tw, "%s: ", attr.Name)
			for _, v := range attr.Values {
				fmt.Fprintln(tw, "\t", v)
			}
		}

	}
	err = tw.Flush()
	if err != nil {
		log.Println(err)
		return
	}
}

type userInfo struct {
	username string
	userdn   string
	password string
}

func (lw *ldapWeb) getUserInfo(r *http.Request) (*userInfo, error) {

	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	username := r.FormValue("username")
	return &userInfo{
		username: username,
		userdn:   getBaseDN(lw.config.dnTemplate, username),
		password: r.FormValue("password"),
	}, nil

}
