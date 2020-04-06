package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	fdk "github.com/fnproject/fdk-go"
	"github.com/oracle/oci-go-sdk/common/auth"
	"github.com/oracle/oci-go-sdk/secrets"
	"encoding/base64"
)

func main() {
	fdk.Handle(fdk.HandlerFunc(ociAuthHandler))
}


// validates an IDCS token


func ociAuthHandler(ctx context.Context, in io.Reader, out io.Writer) {

    URL_INTROSPECT_OCID := "ocid1.vaultsecret.YOUR_VAULT"
	AuthInfo_OCID := "ocid1.vaultsecret.YOUR_VAULT"
	

	rp, err := auth.ResourcePrincipalConfigurationProvider()
	if err != nil {
		fmt.Fprintf(out,"Error  ResourcePrincipalConfigurationProvider %v", err)
		panic(err)
		return
	}

	NewSecretsClient, err := secrets.NewSecretsClientWithConfigurationProvider(rp)
	if err != nil {
		fmt.Fprintf(out,"Error secrets.NewSecretsClientWithConfigurationProvider %v", err)
		panic(err)
		return
	}
	
	NewSecretsClient.SetRegion("eu-frankfurt-1")
	
	URL_INTROSPECT := secrets.GetSecretBundleRequest {
	SecretId : &URL_INTROSPECT_OCID,
	}
	
	GetSecretBundleResponse, err := NewSecretsClient.GetSecretBundle(ctx,  URL_INTROSPECT) 
	fmt.Fprintf(out,"%v\n", GetSecretBundleResponse.SecretBundle)
    URL_INTROSPECT_secret := GetSecretBundleResponse.SecretBundle
	
	// var loc_Bund64 secrets.Base64SecretBundleContentDetails
	var loc_secret = URL_INTROSPECT_secret.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
  
    Dec_string_URL, _ := base64.StdEncoding.DecodeString(*loc_secret.Content)
    
	AuthInfo := secrets.GetSecretBundleRequest {
	SecretId : &AuthInfo_OCID,
	}
	
	GetSecretBundleResponse, err = NewSecretsClient.GetSecretBundle(ctx,  AuthInfo) 
	fmt.Fprintf(out,"%v\n", GetSecretBundleResponse.SecretBundle)
    AuthInfo_secret := GetSecretBundleResponse.SecretBundle	
    loc_secret = AuthInfo_secret.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	Dec_AuthInfo, _ := base64.StdEncoding.DecodeString(*loc_secret.Content)
	
	
	fmt.Fprintf(out,"Dec_string_URL =>%s\n", Dec_string_URL)
	fmt.Fprintf(out,"Dec_AuthInfo =>%s\n", Dec_AuthInfo)	


	var Reply_APi_trsf_loc Reply_APi_trsf
	var Rep_Gat Reply_APi_gateway
		
	time_now := time.Now().Add(time.Hour * -1).Format(time.RFC3339)
	error_rep := Reply_APi_gateway{
		Active:          false,
		ExpiresAt:       time_now,
		WwwAuthenticate: "Bearer realm=\"hacker-dot.com\"",
	}

	fmt.Fprintf(out,"Auth is invocked now: %s\n",time_now)
	fmt.Fprintf(out,"Validate_token start at %s \n", time_now)

	var msgToken MessageToken
	json.NewDecoder(in).Decode(&msgToken)

	if (len(msgToken.Token) == 0) || (msgToken.Type != "TOKEN") {
	    fmt.Fprintf(out,"the JSON TOKEN argument is empty\n")
 
		data, _ := json.Marshal(error_rep)
		fdk.WriteStatus(out, 400)
		fdk.SetHeader(out, "Error-Type", "TOKEN EMPTY")
		out.Write(data)
		return
	}


		url := fmt.Sprintf("%s", Dec_string_URL)
		method := "POST"
		var token = "token=" + msgToken.Token

		fmt.Fprintf(out,"token for the introscpection request =>%s\n", token)

		payload_repl := strings.NewReader(token)
		client_rep := &http.Client{}
		req_rep, err := http.NewRequest(method, url, payload_repl)

		if err != nil {
			fmt.Fprintf(out,"Token validation error\n", err)
			Rep_Gat.Active = false
		} else {
    

		encreyp_auth := fmt.Sprintf("Basic %s", Dec_AuthInfo)
		req_rep.Header.Add("Authorization", encreyp_auth)
		req_rep.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res_rep, _ := client_rep.Do(req_rep)
		defer res_rep.Body.Close()
		body_rep, _ := ioutil.ReadAll(res_rep.Body)


		err = json.Unmarshal(body_rep, &Rep_Gat)
		err = json.Unmarshal(body_rep, &Reply_APi_trsf_loc)
        }

		if Rep_Gat.Active != true {
			fdk.WriteStatus(out, 400)
			fdk.SetHeader(out, "Error-Type", "INVALID TOKEN")
			fdk.SetHeader(out, "TOKEN-content", msgToken.Token)
			data, _ := json.Marshal(error_rep)
			out.Write(data)
			return
		}

		
		Rep_Gat.ExpiresAt = time.Now().Add(time.Hour * -1).Format(time.RFC3339)
		data, err := json.Marshal(Rep_Gat)
		jsonReplyIDCS := string(data)
		fdk.SetHeader(out, "TOKEN-Content", msgToken.Token)
		fdk.WriteStatus(out, 200)
		out.Write(data)
 

}



type Reply_APi_trsf struct {
	Active    bool     `json:"active"`
	Scope     string    `json:"scope"`
	ClientID  string   `json:"client_id"`
	Principal string   `json:"prn"`
	Context   []string `json:"context"`
	ExpiresAt int64    `json:"exp"`
	Token_type     string   `json:"token_type"`
}

type Reply_APi_gateway struct {
	Active          bool     `json:"active"`
	Scope           string   `json:"scope"`
	ClientID        string   `json:"client_id"`
	Principal       string   `json:"prn"`
	ExpiresAt       string   `json:"expiresAt"`
	Context         []string `json:"context"`
	WwwAuthenticate string   `json:"wwwAuthenticate"`
	Token_type     string   `json:"token_type"`
}

type MessageToken struct {
	Token string `json:"token"`
	Type   string `json:"type"`
	Expires_in   int64  `json:"expires_in"`
}

type API_Input_MessageToken struct {
	Token string `json:"token"`
	Type   string `json:"type"`
	Expires_in   int64  `json:"expires_in"`
}



