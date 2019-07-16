package main

import (
	"spidproject/spidsaml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

var sp *spidsaml.SP
var spidSession *spidsaml.Session
var authnReqID, logoutReqID string

func main()  {

	// Initialize our SPID object with information about this Service Provider
	sp = &spidsaml.SP{
		EntityID: "http://54.164.84.39:8080/",
		KeyFile:  "data/key/sp.key",
		CertFile: "data/key/sp.pem",
		AssertionConsumerServices: []string{
			"http://54.164.84.39:8080/spid-sso",
		},
		SingleLogoutServices: map[string]spidsaml.SAMLBinding{
			"http://54.164.84.39:8080/spid-slo": spidsaml.HTTPRedirect,
		},
		AttributeConsumingServices: []spidsaml.AttributeConsumingService{
			{
				ServiceName: "Service 1",
				Attributes:  []string{"fiscalNumber", "name", "familyName", "dateOfBirth"},
			},
		},
	}

	// Load Identity Providers from their XML metadata
	err := sp.LoadIDPMetadata("data/idp_metadata")
	if err != nil {
		fmt.Print("Failed to load IdP metadata: ")
		fmt.Println(err)
		return
	}

	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("templates/css"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("templates/img"))))
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("templates/js"))))
	http.Handle("/logo/", http.StripPrefix("/logo/", http.FileServer(http.Dir("templates/logo"))))


	http.HandleFunc("/", index)
	http.HandleFunc("/metadata", metadata)
	http.HandleFunc("/spid-login", spidLogin)
	http.HandleFunc("/spid-sso", spidSSO)
	http.HandleFunc("/logout", spidLogout)
	http.HandleFunc("/spid-slo", spidSLO)

	log.Println(http.ListenAndServe(getPort(), nil))
}

func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
	}
	return ":8080"

}

func index(writer http.ResponseWriter, request *http.Request) {
	if spidSession == nil {
		t, err := template.ParseFiles("templates/index.html")
		if err != nil {
			log.Print("template parsing error: ", err)
		}
		err = t.Execute(writer, nil)
		if err != nil {
			log.Print("template executing error: ", err)
		}
	} else {
		t, err := template.ParseFiles("templates/data.html")
		if err != nil {
			log.Print("template parsing error: ", err)
		}
		err = t.Execute(writer, spidSession)
		if err != nil {
			log.Print("template executing error: ", err)
		}
	}
}

func metadata(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/xml")
	log.Println(io.WriteString(writer, sp.Metadata()))
}

func spidLogin(writer http.ResponseWriter, request *http.Request) {
	var idpName = ""
	log.Println(request.ParseForm())
	for key := range request.Form {
		idpName = key
	}

	if strings.Contains(idpName, "spid") {
		idpName = "register_id"
	}
	if strings.Contains(idpName, "locale") {
		idpName = "localhost_id"
	}
	if strings.Contains(idpName, "online") {
		idpName = "gov_id"
	}

	var idpLink = ""
	idpName = idpName[:len(idpName)-3]
	for entityID := range sp.IDP {
		if strings.Contains(entityID, idpName) {
			idpLink = entityID
			break
		}
	}
	idp, err := sp.GetIDP(idpLink)
	if err != nil {
		http.Error(writer, "Invalid IdP selected", http.StatusBadRequest)
		return
	}
	authnreq := sp.NewAuthnRequest(idp)
	authnreq.AcsIndex = 0
	authnreq.AttrIndex = 0
	authnreq.Level = 1
	authnReqID = authnreq.ID
	//writer.Write(authnreq.PostForm())
	http.Redirect(writer, request, authnreq.RedirectURL(), http.StatusSeeOther)
}

func spidSSO(writer http.ResponseWriter, request *http.Request) {
	log.Println(request.ParseForm())
	response, err := sp.ParseResponse(
		request,
		authnReqID,
	)
	authnReqID = ""
	if err != nil {
		fmt.Printf("Bad Response received: %s\n", err)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if response.Success() {
		spidSession = response.Session()
		http.Redirect(writer, request, "/", http.StatusSeeOther)
	} else {
		log.Println(fmt.Fprintf(writer, "Authentication Failed: %s (%s)", response.StatusMessage(), response.StatusCode2()))
	}
}

func spidLogout(writer http.ResponseWriter, request *http.Request) {
	if spidSession == nil {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	logoutreq, err := sp.NewLogoutRequest(spidSession)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	logoutReqID = logoutreq.ID
	http.Redirect(writer, request, logoutreq.RedirectURL(), http.StatusSeeOther)
}

func spidSLO(writer http.ResponseWriter, request *http.Request) {
	if spidSession == nil {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	log.Println(request.ParseForm())
	if (request.Form.Get("SAMLResponse") != "" || request.URL.Query().Get("SAMLResponse") != "") && logoutReqID != "" {
		_, err := sp.ParseLogoutResponse(
			request,
			logoutReqID, // Match the ID of our logout request for increased security.
		)
		if err != nil {
			fmt.Printf("Bad LogoutResponse received: %s\n", err)
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		logoutReqID = ""
		spidSession = nil
		fmt.Println("Session successfully destroyed.")
		http.Redirect(writer, request, "/", http.StatusSeeOther)
	} else if request.Form.Get("SAMLRequest") != "" || request.URL.Query().Get("SAMLRequest") != "" {
		logoutreq, err := sp.ParseLogoutRequest(request)

		if err != nil {
			fmt.Printf("Bad LogoutRequest received: %s\n", err)
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		status := spidsaml.SuccessLogout
		if logoutreq.SessionIndex() == spidSession.SessionIndex {
			spidSession = nil
		} else {
			status = spidsaml.PartialLogout
			fmt.Printf("SAML LogoutRequest session (%s) does not match current SPID session (%s)\n", logoutreq.SessionIndex(), spidSession.SessionIndex)
		}

		logoutres, err := sp.NewLogoutResponse(logoutreq, status)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		http.Redirect(writer, request, logoutres.RedirectURL(), http.StatusSeeOther)
	} else {
		http.Error(writer, "Invalid request", http.StatusBadRequest)
	}

}
