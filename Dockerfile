FROM golang:1.10 as builder

WORKDIR /go/src/github.com/dolanor/ldap-web
COPY . ./

RUN go get -v .

FROM debian:stable

WORKDIR /
COPY --from=builder /go/bin/ldap-web .
CMD [ "./ldap-web" ]
