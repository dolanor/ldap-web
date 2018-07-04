package main

import (
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
	displayLoginPage = `<!DOCTYPE html>
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
			<input type="text" class="form-control form-lg" placeholder="Username" name="username" id="username">
			<input type="password" class="form-control form-lg" placeholder="Password" name="password" id="password">
			<button type="submit" class="btn btn-primary form-lg submit-btn">Login</button>
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

func handleLogin(cfg *config, lw ldapWeb) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var username, userdn, password string

		sess, err := lw.sessionStore.Get(r, "session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, ok := sess.Values["username"]; !ok {
			err := r.ParseForm()
			if err != nil {
				http.Error(w, "couldn't parse form", 400)
				return
			}
			username = r.FormValue("username")
			userdn = getBaseDN(cfg.dnTemplate, username)
			password = r.FormValue("password")

			sess.Values["username"] = username
			sess.Values["userdn"] = userdn
			sess.Values["password"] = password

			err = sess.Save(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			username = sess.Values["username"].(string)
			userdn = sess.Values["userdn"].(string)
			password = sess.Values["password"].(string)
		}

		srch, err := ldapSearch(cfg, username, userdn, password)
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
}

func displayLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Println("in displayLogin")
	templateFuncs := template.FuncMap{"noescape": noescape}
	t := template.Must(template.New("displayLogin").Funcs(templateFuncs).Parse(displayLoginPage))
	err := t.Execute(w, nil)
	if err != nil {
		fmt.Println("error:", err)
	}
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

func (lw *ldapWeb) handleMailaliasCreate(w http.ResponseWriter, r *http.Request) {

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

	r.HandleFunc("/", displayLogin).Methods("GET")
	r.HandleFunc("/auth", handleLogin(cfg, lw)).Methods("POST")
	r.HandleFunc("/mailalias", lw.handleMailaliasCreate).Methods("POST")

	http.ListenAndServe(":1111", r)
}
