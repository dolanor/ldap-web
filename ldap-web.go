package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"text/tabwriter"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"gopkg.in/ldap.v2"
)

const (
	displayInputPage = `<!DOCTYPE html>
<html>
<head>
	<title>Login</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" type="text/css">
    {{noescape	"<!--[if lt IE 9]><script src='/html5shiv/dist/html5shiv.min.js'></script><script src='/Respond/dest/respond.min.js'></script><![endif]-->"}}
    <link rel="shortcut icon" href="/bootstrap/img/favicon.ico">
	<link href="//maxcdn.bootstrapcdn.com/font-awesome/4.2.0/css/font-awesome.min.css" rel="stylesheet">
</head>
<body>
	<form class="form-horizontal" role="form" action="/auth" method="POST">
			<input type="text" class="form-control form-lg" placeholder="Current Username" name="username" id="username">
			<input type="password" class="form-control form-lg" placeholder="Current Password" name="password" id="password">

			<button type="submit" formaction="/user" class="btn btn-primary form-lg submit-btn">Display user info</button>

			<input type="text" class="form-control form-lg" placeholder="New Mail Alias" name="newmailalias" id="newmailalias">
			<button type="submit" formaction="/mailalias" class="btn btn-primary form-lg submit-btn">Add Mail Alias</button>

			<input type="password" class="form-control form-lg" placeholder="New Password" name="newpassword" id="newpassword">
			<input type="password" class="form-control form-lg" placeholder="Confirm Password" name="newpassword2" id="newpassword2">
			<button type="submit" formaction="/password" class="btn btn-primary form-lg submit-btn">Change Password</button>
	</form>
</body>
</html>
`
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

type ldapWeb struct {
	musessions sync.Mutex
	sessions   map[int64]session

	sessionStore sessions.Store

	config *config
}

func displayForm(w http.ResponseWriter, r *http.Request) {
	fmt.Println("in displayForm")
	templateFuncs := template.FuncMap{"noescape": noescape}
	t := template.Must(template.New("displayForm").Funcs(templateFuncs).Parse(displayInputPage))
	err := t.Execute(w, nil)
	if err != nil {
		fmt.Println("error:", err)
	}
}

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

func main() {
	cfg := loadCfg()
	lw := ldapWeb{
		sessions:     make(map[int64]session),
		sessionStore: sessions.NewCookieStore([]byte("secret")),
		config:       cfg,
	}
	r := mux.NewRouter()

	jmw := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	_ = jmw

	r.HandleFunc("/", displayForm).Methods("GET")
	r.HandleFunc("/user", lw.displayUserInfo).Methods("POST")
	r.HandleFunc("/password", lw.handleModifyPassword).Methods("POST")
	r.HandleFunc("/mailalias", lw.handleAddMailalias).Methods("POST")

	http.ListenAndServe(":1111", r)
}
