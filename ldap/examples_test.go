package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/userhive/asn1/ldap/control"
)

// This example demonstrates how to bind a connection to an ldap user
// allowing access to restricted attributes that user has access to
func ExampleConn_Bind() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	err = l.Bind("cn=read-only-admin,dc=example,dc=com", "password")
	if err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates how to use the search interface
func ExampleConn_Search() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	searchRequest := NewClientSearchRequest(
		"dc=example,dc=com", // The base dn to search
		ScopeWholeSubtree, DerefAliasesNever, 0, 0, false,
		"(&(objectClass=organizationalPerson))", // The filter to apply
		[]string{"dn", "cn"},                    // A list attributes to retrieve
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}
}

// This example demonstrates how to start a TLS connection
func ExampleConn_StartTLS() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	// Reconnect with TLS
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatal(err)
	}
	// Operations via l are now encrypted
}

// This example demonstrates how to compare an attribute with a value
func ExampleConn_Compare() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	matched, err := l.Compare("cn=user,dc=example,dc=com", "uid", "someuserid")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(matched)
}

func ExampleConn_PasswordModify_admin() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	err = l.Bind("cn=admin,dc=example,dc=com", "password")
	if err != nil {
		log.Fatal(err)
	}
	passwordModifyRequest := NewPasswordModifyRequest("cn=user,dc=example,dc=com", "", "NewPassword")
	_, err = l.PasswordModify(passwordModifyRequest)
	if err != nil {
		log.Fatalf("Password could not be changed: %s", err.Error())
	}
}

func ExampleConn_PasswordModify_generatedPassword() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	err = l.Bind("cn=user,dc=example,dc=com", "password")
	if err != nil {
		log.Fatal(err)
	}
	passwordModifyRequest := NewPasswordModifyRequest("", "OldPassword", "")
	passwordModifyResponse, err := l.PasswordModify(passwordModifyRequest)
	if err != nil {
		log.Fatalf("Password could not be changed: %s", err.Error())
	}
	generatedPassword := passwordModifyResponse.GeneratedPassword
	log.Printf("Generated password: %s\n", generatedPassword)
}

func ExampleConn_PasswordModify_setNewPassword() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	err = l.Bind("cn=user,dc=example,dc=com", "password")
	if err != nil {
		log.Fatal(err)
	}
	passwordModifyRequest := NewPasswordModifyRequest("", "OldPassword", "NewPassword")
	_, err = l.PasswordModify(passwordModifyRequest)
	if err != nil {
		log.Fatalf("Password could not be changed: %s", err.Error())
	}
}

func ExampleConn_Modify() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	// Add a description, and replace the mail attributes
	modify := NewModifyRequest("cn=user,dc=example,dc=com", nil)
	modify.Add("description", []string{"An example user"})
	modify.Replace("mail", []string{"user@example.org"})
	err = l.Modify(modify)
	if err != nil {
		log.Fatal(err)
	}
}

// This example shows how a typical application can verify a login attempt
func Example_userAuthentication() {
	// The username and password we want to check
	username := "someuser"
	password := "userpassword"
	bindusername := "readonly"
	bindpassword := "password"
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	// Reconnect with TLS
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatal(err)
	}
	// First bind with a read only user
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Fatal(err)
	}
	// Search for the given username
	searchRequest := NewClientSearchRequest(
		"dc=example,dc=com",
		ScopeWholeSubtree, DerefAliasesNever, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", username),
		[]string{"dn"},
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	if len(sr.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
	}
	userdn := sr.Entries[0].DN
	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		log.Fatal(err)
	}
	// Rebind as the read only user for any further queries
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Fatal(err)
	}
}

func Example_beherappolicy() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	controls := []control.Control{
		control.NewBeheraPasswordPolicy(),
	}
	controls = append(controls)
	bindRequest := NewSimpleBindRequest("cn=admin,dc=example,dc=com", "password", controls...)
	r, err := l.SimpleBind(bindRequest)
	ppolicyControl := control.Find(r.Controls, control.ControlBeheraPasswordPolicy.String())
	var ppolicy *control.BeheraPasswordPolicy
	if ppolicyControl != nil {
		ppolicy = ppolicyControl.(*control.BeheraPasswordPolicy)
	} else {
		log.Printf("ppolicyControl response not available.\n")
	}
	if err != nil {
		errStr := "ERROR: Cannot bind: " + err.Error()
		if ppolicy != nil && ppolicy.Error >= 0 {
			errStr += ":" + ppolicy.ErrorString
		}
		log.Print(errStr)
	} else {
		logStr := "Login Ok"
		if ppolicy != nil {
			if ppolicy.Expire >= 0 {
				logStr += fmt.Sprintf(". Password expires in %d seconds\n", ppolicy.Expire)
			} else if ppolicy.Grace >= 0 {
				logStr += fmt.Sprintf(". Password expired, %d grace logins remain\n", ppolicy.Grace)
			}
		}
		log.Print(logStr)
	}
}

func Example_vchuppolicy() {
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	l.Debug = true
	bindRequest := NewSimpleBindRequest("cn=admin,dc=example,dc=com", "password", nil)
	r, err := l.SimpleBind(bindRequest)
	passwordMustChangeControl := control.Find(r.Controls, control.ControlVChuPasswordMustChange.String())
	var passwordMustChange *control.VChuPasswordMustChange
	if passwordMustChangeControl != nil {
		passwordMustChange = passwordMustChangeControl.(*control.VChuPasswordMustChange)
	}
	if passwordMustChange != nil && passwordMustChange.MustChange {
		log.Printf("Password Must be changed.\n")
	}
	passwordWarningControl := control.Find(r.Controls, control.ControlVChuPasswordWarning.String())
	var passwordWarning *control.VChuPasswordWarning
	if passwordWarningControl != nil {
		passwordWarning = passwordWarningControl.(*control.VChuPasswordWarning)
	} else {
		log.Printf("ppolicyControl response not available.\n")
	}
	if err != nil {
		log.Print("ERROR: Cannot bind: " + err.Error())
	} else {
		logStr := "Login Ok"
		if passwordWarning != nil {
			if passwordWarning.Expire >= 0 {
				logStr += fmt.Sprintf(". Password expires in %d seconds\n", passwordWarning.Expire)
			}
		}
		log.Print(logStr)
	}
}

// This example demonstrates how to use Paging to manually execute a
// paginated search request instead of using SearchWithPaging.
func ExamplePaging_manualPaging() {
	conn, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	var pageSize uint32 = 32
	searchBase := "dc=example,dc=com"
	filter := "(objectClass=group)"
	pagingControl := control.NewPaging(pageSize)
	attributes := []string{}
	controls := []control.Control{pagingControl}
	for {
		request := NewClientSearchRequest(searchBase, ScopeWholeSubtree, DerefAliasesAlways, 0, 0, false, filter, attributes, controls...)
		response, err := conn.Search(request)
		if err != nil {
			log.Fatalf("Failed to execute search request: %s", err.Error())
		}
		// [do something with the response entries]
		// In order to prepare the next request, we check if the response
		// contains another Paging object and a not-empty cookie and
		// copy that cookie into our pagingControl object:
		updatedControl := control.Find(response.Controls, control.ControlPaging.String())
		if ctrl, ok := updatedControl.(*control.Paging); ctrl != nil && ok && len(ctrl.Cookie) != 0 {
			pagingControl.SetCookie(ctrl.Cookie)
			continue
		}
		// If no new paging information is available or the cookie is empty, we
		// are done with the pagination.
		break
	}
}

// This example demonstrates how to use EXTERNAL SASL with TLS client certificates.
func ExampleConn_ExternalBind() {
	ldapCert := "/path/to/cert.pem"
	ldapKey := "/path/to/key.pem"
	ldapCAchain := "/path/to/ca_chain.pem"
	// Load client cert and key
	cert, err := tls.LoadX509KeyPair(ldapCert, ldapKey)
	if err != nil {
		log.Fatal(err)
	}
	// Load CA chain
	caCert, err := ioutil.ReadFile(ldapCAchain)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	// Setup TLS with ldap client cert
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}
	// connect to ldap server
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	// reconnect using tls
	err = l.StartTLS(tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	// sasl external bind
	err = l.ExternalBind()
	if err != nil {
		log.Fatal(err)
	}
	// Conduct ldap queries
}

// This example shows how to rename an entry without moving it
func ExampleConn_ModifyDN_renameNoMove() {
	conn, err := DialURL("ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()
	_, err = conn.SimpleBind(&ClientSimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// just rename to uid=new,ou=people,dc=example,dc=org:
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "")
	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}

// This example shows how to rename an entry and moving it to a new base
func ExampleConn_ModifyDN_renameAndMove() {
	conn, err := DialURL("ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()
	_, err = conn.SimpleBind(&ClientSimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// rename to uid=new,ou=people,dc=example,dc=org and move to ou=users,dc=example,dc=org ->
	// uid=new,ou=users,dc=example,dc=org
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "ou=users,dc=example,dc=org")
	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}

// This example shows how to move an entry to a new base without renaming the RDN
func ExampleConn_ModifyDN_moveOnly() {
	conn, err := DialURL("ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()
	_, err = conn.SimpleBind(&ClientSimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// move to ou=users,dc=example,dc=org -> uid=user,ou=users,dc=example,dc=org
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=user", true, "ou=users,dc=example,dc=org")
	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}