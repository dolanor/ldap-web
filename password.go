package main

import (
	"errors"
	"fmt"
	"net/http"
)

func (lw *ldapWeb) getNewPassword(r *http.Request) (string, error) {

	err := r.ParseForm()
	if err != nil {
		return "", err
	}
	newpassword := r.FormValue("newpassword")
	newpassword2 := r.FormValue("newpassword2")
	if newpassword != newpassword2 {
		return "", errors.New("passwords don't match")
	}

	return newpassword, nil
}

func (lw *ldapWeb) handleModifyPassword(w http.ResponseWriter, r *http.Request) {
	u, err := lw.getUserInfo(r)
	if err != nil {
		http.Error(w, "couldn't parse form: "+err.Error(), http.StatusInternalServerError)
		return
	}

	p, err := lw.getNewPassword(r)
	if err != nil {
		http.Error(w, "couldn't parse form: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = ldapChangePassword(lw.config, u.username, u.userdn, u.password, p)
	if err != nil {
		http.Error(w, fmt.Sprintf("couldn't create new mailalias: %+v\n", err), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "password changed!\n")
}
