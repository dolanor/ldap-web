package main

import "html/template"

func noescape(s string) template.HTML {
	return template.HTML(s)
}
