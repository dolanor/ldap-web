package main

import (
	"fmt"
	"html/template"
	"net/http"
	"sync"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
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
