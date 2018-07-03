package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"text/tabwriter"

	"gopkg.in/ldap.v2"
)

const (
	displayLoginPage = `<!DOCTYPE html>
<html>
<head>
	<title>Login</title>
</head>
<body>
	<form class="form-horizontal" role="form" action="/login" method="POST">
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

func handleLogin(cfg *config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "couldn't parse form", 400)
			return
		}
		username := r.FormValue("username")
		userdn := getBaseDN(cfg.dnTemplate, username)
		password := r.FormValue("password")

		srch, err := ldapSearch(cfg, username, userdn, password)
		if err != nil {
			http.Error(w, fmt.Sprintf("couldn't search LDAP: %+v\n", err), 500)
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
	t := template.Must(template.New("displayLogin").Parse(displayLoginPage))
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
	config config
}

func main() {
	cfg := loadCfg()

	http.HandleFunc("/", displayLogin)
	http.HandleFunc("/login", handleLogin(cfg))
	http.ListenAndServe(":1111", nil)
}
