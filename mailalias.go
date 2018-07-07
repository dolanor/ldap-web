package main

import (
	"fmt"
	"net/http"
)

func (lw *ldapWeb) handleAddMailalias(w http.ResponseWriter, r *http.Request) {
	u, err := lw.getUserInfo(r)
	if err != nil {
		http.Error(w, "couldn't parse form: "+err.Error(), http.StatusInternalServerError)
		return
	}

	m, err := lw.getNewMailalias(r)
	if err != nil {
		http.Error(w, "couldn't parse form: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = ldapAddMailalias(lw.config, u.username, u.userdn, u.password, m)
	if err != nil {
		http.Error(w, fmt.Sprintf("couldn't create new mailalias: %+v\n", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "%s mail alias added!\n", m)
}

func (lw *ldapWeb) getNewMailalias(r *http.Request) (string, error) {

	err := r.ParseForm()
	if err != nil {
		return "", err
	}
	newmailalias := r.FormValue("newmailalias")
	return newmailalias, nil
}
