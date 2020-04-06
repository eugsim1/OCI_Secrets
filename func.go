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
_	"github.com/oracle/oci-go-sdk/common"
	"github.com/oracle/oci-go-sdk/common/auth"
	"github.com/oracle/oci-go-sdk/secrets"
	"encoding/base64"
)

func main() {
	fdk.Handle(fdk.HandlerFunc(ociAuthHandler))
}


// validates an IDCS token


func ociAuthHandler(ctx context.Context, in io.Reader, out io.Writer) {

    URL_INTROSPECT_OCID := "ocid1.vaultsecret.oc1.eu-frankfurt-1.amaaaaaa4g77oeyaycr4fsrj74zy5feumszh7avg34xtsebvjffstqpeqcoa"
	AuthInfo_OCID := "ocid1.vaultsecret.oc1.eu-frankfurt-1.amaaaaaa4g77oeyafmtnbsgfscfn7wfw24azkv2j26h3ch5fcyhredetvkhq"
	

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
	fmt.Fprintf(out,"content of the token=>%s\n", string(msgToken.Token))
	fmt.Fprintf(out,"content of the token=>%v\n", msgToken.Token)


	if (len(msgToken.Token) == 0) || (msgToken.Type != "TOKEN") {
	    fmt.Fprintf(out,"the JSON TOKEN argument is empty\n")
 
		data, _ := json.Marshal(error_rep)
		fdk.WriteStatus(out, 400)
		fdk.SetHeader(out, "Error-Type", "TOKEN EMPTY")
		out.Write(data)
		return
	}

	// the goal is to test the fakeauth function with the following content tokens
	// VALID => auth to IDCS is ok
	// INVALID => auth to IDCS has failed

	if msgToken.Token == "TESTVALID" {
		fmt.Fprintf(out,"FAKE TEST:the JSON TOKEN is VALID\n")

		time_expires := time.Now().Add(time.Hour * -1).Format(time.RFC3339)
		rep_fake := Reply_APi_gateway{
			Active:          true,
			ExpiresAt:       time_expires,
			ClientID:        "eugene.simos@oracle.com",
			Principal:       "pythia@greece.com",
			Context:       []string{"email:eugene.simos@oracle.com", "function_called:hello", "context_used:POC_fake_auth", },
			//Scope:         []string{"read:hello","create:hello","update:hello", "delete:hello", "allops:hello"},
			Scope:           "get_approles address phone openid profile groups approles email get_groups",
			WwwAuthenticate: "Bearer realm=\"goodtoken.com\"",
		}
		fdk.SetHeader(out, "TOKEN-Type", "FAKE VALID TOKEN")
		fdk.SetHeader(out, "TOKEN-Content", msgToken.Token)

		fdk.WriteStatus(out, 200)
		data, _ := json.Marshal(rep_fake)
		jsonStr := string(data)
		fmt.Fprintf(out,"Reponse send%s\n",jsonStr)
		fdk.SetHeader(out, "Reponse send", jsonStr)
		out.Write(data)
		return
	} else if msgToken.Token == "TESTINVALID" {
		fmt.Fprintf(out,"FAKE TEST:the JSON TOKEN is INVALID\n")
		fmt.Fprintf(out,"The content token tested at %s is %s\n", time_now, msgToken.Token)

		fdk.WriteStatus(out, 400)
		fdk.SetHeader(out, "TOKEN-Type", "FAKE INVALID TOKEN")
		fdk.SetHeader(out, "TOKEN-Content", msgToken.Token)
		fdk.WriteStatus(out, 400)
		data, _ := json.Marshal(error_rep)
		//jsonStr := string(data)
		out.Write(data)
		return
	} else {
		fmt.Fprintf(out,"Auth :the JSON TOKEN COULD BE INVALID\n")
		fmt.Fprintf(out,"The content token tested at %s is %s\n", time_now, msgToken.Token)


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
			fmt.Fprintf(out,"THE IDCS JSON TOKEN is INVALID\n")
			fmt.Fprintf(out,"Token content tested at %s %s\n", token, time_now)
			fdk.WriteStatus(out, 400)
			fdk.SetHeader(out, "Error-Type", "INVALID TOKEN")
			fdk.SetHeader(out, "TOKEN-content", msgToken.Token)
			data, _ := json.Marshal(error_rep)
			out.Write(data)
			return
		}

		fmt.Fprintf(out,"THE IDCS JSON TOKEN is VALID\n")
		fmt.Fprintf(out,"Token content tested at %s %s\n", token, time_now)
		Rep_Gat.ExpiresAt = time.Now().Add(time.Hour * -1).Format(time.RFC3339)
		data, err := json.Marshal(Rep_Gat)
		jsonReplyIDCS := string(data)
		fmt.Fprintf(out,"\n----\n%s\n--------\n",jsonReplyIDCS)
		fdk.SetHeader(out, "TOKEN-Content", msgToken.Token)
		fdk.WriteStatus(out, 200)
		out.Write(data)
	}

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



