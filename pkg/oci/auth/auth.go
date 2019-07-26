package auth

import "net/http"

type Authorizer interface {
	Authorize(req *http.Request) error
}

type BearerTokenAuthorizer struct {
	AccessToken string
}

func (ata *BearerTokenAuthorizer) Authorize(req *http.Request) error {
	req.Header.Add("Authorization", "Bearer "+ata.AccessToken)
	return nil
}

func NewBearerTokenAuthorizer(accessToken string) *BearerTokenAuthorizer {
	return &BearerTokenAuthorizer{AccessToken: accessToken}
}
