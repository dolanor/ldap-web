FROM golang:1.20 as builder

WORKDIR /go/src/github.com/dolanor/ldap-web
COPY . ./

RUN go install -v .

FROM debian:stable

WORKDIR /
COPY --from=builder /go/bin/ldapweb .
CMD [ "./ldapweb" ]
