package main

import (
	"encoding/gob"
	"spidproject/spidsaml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"github.com/gorilla/sessions"
)

type User struct {
	SpidSession *spidsaml.Session
	AuthnReqID string
	LogoutReqID string
}

var sp *spidsaml.SP
var store *sessions.CookieStore

func init()  {

	store = sessions.NewCookieStore([]byte("spidproject"))

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   30 * 60,
		HttpOnly: true,
	}

	gob.Register(&User{})
}

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
	session, err := store.Get(request, "cookie-name")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	user := getUser(session)
	if user.SpidSession == nil {
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
		err = t.Execute(writer, user.SpidSession)
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
	session, err := store.Get(request, "cookie-name")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	user := getUser(session)
	var idpName = ""
	log.Println(request.ParseForm())
	for key := range request.Form {
		idpName = key
	}

	if strings.Contains(idpName, "spid") {
		idpName = "register_id"
	}
	if strings.Contains(idpName, "locale") {
		idpName = "3.220.251.158_id"
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
	user.AuthnReqID = authnreq.ID

	session.Values["user"] = user
	err = session.Save(request, writer)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(writer, request, authnreq.RedirectURL(), http.StatusSeeOther)
}

func spidSSO(writer http.ResponseWriter, request *http.Request) {

	session, err := store.Get(request, "cookie-name")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	user := getUser(session)
	log.Println(request.ParseForm())
	response, err := sp.ParseResponse(
		request,
		user.AuthnReqID,
	)
	fmt.Println(user.AuthnReqID)
	user.AuthnReqID = ""
	if err != nil {
		fmt.Printf("Bad Response received: %s\n", err)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if response.Success() {
		user.SpidSession = response.Session()
		fmt.Println(user.SpidSession)
		user.SpidSession.AssertionXML = nil

		session.Values["user"] = user
		err = session.Save(request, writer)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(writer, request, "/", http.StatusSeeOther)
	} else {
		log.Println(fmt.Fprintf(writer, "Authentication Failed: %s (%s)", response.StatusMessage(), response.StatusCode2()))
	}
}

func spidLogout(writer http.ResponseWriter, request *http.Request) {

	session, err := store.Get(request, "cookie-name")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	user := getUser(session)

	if user.SpidSession == nil {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	logoutreq, err := sp.NewLogoutRequest(user.SpidSession)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	user.LogoutReqID = logoutreq.ID

	session.Values["user"] = user
	err = session.Save(request, writer)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(writer, request, logoutreq.RedirectURL(), http.StatusSeeOther)
}

func spidSLO(writer http.ResponseWriter, request *http.Request) {

	session, err := store.Get(request, "cookie-name")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	user := getUser(session)

	if user.SpidSession == nil {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	log.Println(request.ParseForm())
	if (request.Form.Get("SAMLResponse") != "" || request.URL.Query().Get("SAMLResponse") != "") && user.LogoutReqID != "" {
		_, err := sp.ParseLogoutResponse(
			request,
			user.LogoutReqID, // Match the ID of our logout request for increased security.
		)
		if err != nil {
			fmt.Printf("Bad LogoutResponse received: %s\n", err)
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		user.LogoutReqID = ""
		user.SpidSession = nil
		fmt.Println("Session successfully destroyed.")

		session.Values["user"] = user
		err = session.Save(request, writer)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(writer, request, "/", http.StatusSeeOther)
	} else if request.Form.Get("SAMLRequest") != "" || request.URL.Query().Get("SAMLRequest") != "" {
		logoutreq, err := sp.ParseLogoutRequest(request)

		if err != nil {
			fmt.Printf("Bad LogoutRequest received: %s\n", err)
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		status := spidsaml.SuccessLogout
		if logoutreq.SessionIndex() == user.SpidSession.SessionIndex {
			user.SpidSession = nil
		} else {
			status = spidsaml.PartialLogout
			fmt.Printf("SAML LogoutRequest session (%s) does not match current SPID session (%s)\n", logoutreq.SessionIndex(), user.SpidSession.SessionIndex)
		}

		logoutres, err := sp.NewLogoutResponse(logoutreq, status)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		session.Values["user"] = user
		err = session.Save(request, writer)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(writer, request, logoutres.RedirectURL(), http.StatusSeeOther)
	} else {
		http.Error(writer, "Invalid request", http.StatusBadRequest)
	}

}

func getUser(s *sessions.Session) User {
	val := s.Values["user"]
	var user = &User{}
	user, ok := val.(*User)
	if !ok {
		return User{SpidSession: nil}
	}
	return *user
}
