package main

import (
	"encoding/gob"
	"github.com/globalsign/mgo"
	"github.com/kidstuff/mongostore"
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
var store *mongostore.MongoStore

func init()  {

	dbsess, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}

	store = mongostore.NewMongoStore(dbsess.DB("spidproject").C("spidproject_session"), 1800, true, []byte("secret-key"))

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
				ServiceName: "SpidProject",
				Attributes:  []string{"email","gender", "dateOfBirth", "name", "familyName", "fiscalNumber", "spidCode"},
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
	http.HandleFunc("/error", error)
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

// If we have an active SPID session, display a page with user attributes,
// otherwise show a generic login page containing the SPID button.
func index(writer http.ResponseWriter, request *http.Request) {
	session, err := store.Get(request, "session-key")
	if err != nil {
		//http.Error(writer, err.Error(), http.StatusInternalServerError)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
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

func error(writer http.ResponseWriter, request *http.Request)  {
	t, err := template.ParseFiles("templates/error.html")
	if err != nil {
		log.Print("template parsing error: ", err)
	}
	err = t.Execute(writer, nil)
	if err != nil {
		log.Print("template executing error: ", err)
	}
}

// This endpoint exposes our metadata
func metadata(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/xml")
	log.Println(io.WriteString(writer, sp.Metadata()))
}

// This endpoint initiates SSO through the user-chosen Identity Provider.
func spidLogin(writer http.ResponseWriter, request *http.Request) {

	session, err := store.Get(request, "session-key")
	if err != nil {
		//http.Error(writer, err.Error(), http.StatusInternalServerError)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
		return
	}
	user := getUser(session)

	// Check that we have the mandatory 'idp' parameter and that it matches
	// an available Identity Provider.
	var idpName = ""
	log.Println(request.ParseForm())
	for key := range request.Form {
		idpName = key
	}

	if strings.Contains(idpName, "spid") {
		idpName = "register_id"
	}
	if strings.Contains(idpName, "test") {
		idpName = "3.220.251.158_id"
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
		//http.Error(writer, "Invalid IdP selected", http.StatusBadRequest)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
		return
	}

	// Craft the AuthnRequest.
	authnreq := sp.NewAuthnRequest(idp)
	authnreq.AcsIndex = 0
	authnreq.AttrIndex = 0
	authnreq.Level = 2

	// Save the ID of the Authnreq so that we can check it in the response
	// in order to prevent forgery.
	user.AuthnReqID = authnreq.ID

	session.Values["user"] = user
	if err = sessions.Save(request, writer); err != nil {
		log.Printf("Error saving session: %v", err)
	}

	// Redirect user to the IdP using its HTTP-Redirect binding.
	http.Redirect(writer, request, authnreq.RedirectURL(), http.StatusSeeOther)
}


// This endpoint exposes an AssertionConsumerService for our Service Provider.
// During SSO, the Identity Provider will redirect user to this URL POSTing
// the resulting assertion.
func spidSSO(writer http.ResponseWriter, request *http.Request) {

	session, err := store.Get(request, "session-key")
	if err != nil {
		//http.Error(writer, err.Error(), http.StatusInternalServerError)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
		return
	}
	user := getUser(session)

	// Parse and verify the incoming assertion.
	log.Println(request.ParseForm())
	response, err := sp.ParseResponse(
		request,
		user.AuthnReqID,
	)

	// Clear the ID of the outgoing Authnreq, regardless of the result.
	user.AuthnReqID = ""

	// In case of SSO failure, display an error page.
	if err != nil {
		fmt.Printf("Bad Response received: %s\n", err)
		//http.Error(writer, err.Error(), http.StatusBadRequest)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
		return
	}

	// Log response as required by the SPID rules.
	// Hint: log it in a way that does not mangle whitespace preventing signature from
	// being verified at a later time
	fmt.Printf("SPID Response: %s\n", response.XML)


	if response.Success() {
		// Login successful!

		user.SpidSession = response.Session()
		user.SpidSession.AssertionXML = nil

		session.Values["user"] = user
		err = session.Save(request, writer)
		if err != nil {
			//http.Error(writer, err.Error(), http.StatusInternalServerError)
			http.Redirect(writer, request, "/error", http.StatusSeeOther)
			return
		}

		http.Redirect(writer, request, "/", http.StatusSeeOther)
	} else {
		//log.Println(fmt.Fprintf(writer, "Authentication Failed: %s (%s)", response.StatusMessage(), response.StatusCode2()))
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
	}
}

// This endpoint initiates logout.
func spidLogout(writer http.ResponseWriter, request *http.Request) {

	session, err := store.Get(request, "session-key")
	if err != nil {
		//http.Error(writer, err.Error(), http.StatusInternalServerError)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
		return
	}
	user := getUser(session)

	// If we don't have an open SPID session, do nothing.
	if user.SpidSession == nil {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}

	// Craft the LogoutRequest.
	logoutreq, err := sp.NewLogoutRequest(user.SpidSession)
	if err != nil {
		//http.Error(writer, err.Error(), http.StatusBadRequest)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
		return
	}

	// Save the ID of the LogoutRequest so that we can check it in the response
	// in order to prevent forgery.
	user.LogoutReqID = logoutreq.ID

	session.Values["user"] = user
	err = session.Save(request, writer)
	if err != nil {
		//http.Error(writer, err.Error(), http.StatusInternalServerError)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
		return
	}

	// Redirect user to the Identity Provider for logout.
	http.Redirect(writer, request, logoutreq.RedirectURL(), http.StatusSeeOther)
}

// This endpoint exposes a SingleLogoutService for our Service Provider, using
// a HTTP-POST or HTTP-Redirect binding (this package does not support SOAP).
// Identity Providers can direct both LogoutRequest and LogoutResponse messages
// to this endpoint.
func spidSLO(writer http.ResponseWriter, request *http.Request) {

	session, err := store.Get(request, "session-key")
	if err != nil {
		//http.Error(writer, err.Error(), http.StatusInternalServerError)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
		return
	}
	user := getUser(session)

	if user.SpidSession == nil {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}

	log.Println(request.ParseForm())
	if (request.Form.Get("SAMLResponse") != "" || request.URL.Query().Get("SAMLResponse") != "") && user.LogoutReqID != "" {
		// This is the response to a SP-initiated logout.

		// Parse the response and catch validation errors.
		_, err := sp.ParseLogoutResponse(
			request,
			user.LogoutReqID, // Match the ID of our logout request for increased security.
		)

		// In case of SLO failure, display an error page.
		if err != nil {
			fmt.Printf("Bad LogoutResponse received: %s\n", err)
			//http.Error(writer, err.Error(), http.StatusBadRequest)
			http.Redirect(writer, request, "/error", http.StatusSeeOther)
			return
		}

		// Logout was successful! Clear the local session.
		user.LogoutReqID = ""
		user.SpidSession = nil
		fmt.Println("Session successfully destroyed.")

		session.Values["user"] = user
		err = session.Save(request, writer)
		if err != nil {
			//http.Error(writer, err.Error(), http.StatusInternalServerError)
			http.Redirect(writer, request, "/error", http.StatusSeeOther)
			return
		}
		session.Options.MaxAge = -1

		// Redirect user back to main page.
		http.Redirect(writer, request, "/", http.StatusSeeOther)
	} else if request.Form.Get("SAMLRequest") != "" || request.URL.Query().Get("SAMLRequest") != "" {
		// This is a LogoutRequest (IdP-initiated logout).

		logoutreq, err := sp.ParseLogoutRequest(request)

		if err != nil {
			fmt.Printf("Bad LogoutRequest received: %s\n", err)
			//http.Error(writer, err.Error(), http.StatusBadRequest)
			http.Redirect(writer, request, "/error", http.StatusSeeOther)
			return
		}

		// Now we should retrieve the local session corresponding to the SPID
		// session logoutreq.SessionIndex(). However, since we are implementing a HTTP-POST
		// binding, this HTTP request comes from the user agent so the current user
		// session is automatically the right one. This simplifies things a lot as
		// retrieving another session by SPID session ID is tricky without a more
		// complex architecture.
		status := spidsaml.SuccessLogout
		if logoutreq.SessionIndex() == user.SpidSession.SessionIndex {
			user.SpidSession = nil
		} else {
			status = spidsaml.PartialLogout
			fmt.Printf("SAML LogoutRequest session (%s) does not match current SPID session (%s)\n", logoutreq.SessionIndex(), user.SpidSession.SessionIndex)
		}

		// Craft a LogoutResponse and send it back to the Identity Provider.
		logoutres, err := sp.NewLogoutResponse(logoutreq, status)
		if err != nil {
			//http.Error(writer, err.Error(), http.StatusBadRequest)
			http.Redirect(writer, request, "/error", http.StatusSeeOther)
			return
		}

		session.Values["user"] = user
		err = session.Save(request, writer)
		if err != nil {
			//http.Error(writer, err.Error(), http.StatusInternalServerError)
			http.Redirect(writer, request, "/error", http.StatusSeeOther)
			return
		}
		session.Options.MaxAge = -1

		// Redirect user to the Identity Provider for logout.
		http.Redirect(writer, request, logoutres.RedirectURL(), http.StatusSeeOther)
	} else {
		//http.Error(writer, "Invalid request", http.StatusBadRequest)
		http.Redirect(writer, request, "/error", http.StatusSeeOther)
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
