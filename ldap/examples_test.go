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
func ExampleClientBind() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	if err = cl.Bind("cn=read-only-admin,dc=example,dc=com", "password"); err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates how to use the search interface
func ExampleClientSearch() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	req := NewClientSearchRequest(
		"dc=example,dc=com", // The base dn to search
		ScopeWholeSubtree, DerefAliasesNever, 0, 0, false,
		"(&(objectClass=organizationalPerson))", // The filter to apply
		[]string{"dn", "cn"},                    // A list attributes to retrieve
	)
	res, err := cl.Search(req)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range res.Entries {
		log.Printf("%s: %v", entry.DN, entry.GetAttributeValue("cn"))
	}
}

// This example demonstrates how to start a TLS connection
func ExampleClientStartTLS() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	// Reconnect with TLS
	if err = cl.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		log.Fatal(err)
	}
	// Operations via l are now encrypted
}

// This example demonstrates how to compare an attribute with a value
func ExampleClientCompare() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	matched, err := cl.Compare("cn=user,dc=example,dc=com", "uid", "someuserid")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(matched)
}

func ExampleClientPasswordModifyAdmin() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	if err = cl.Bind("cn=admin,dc=example,dc=com", "password"); err != nil {
		log.Fatal(err)
	}
	req := NewPasswordModifyRequest("cn=user,dc=example,dc=com", "", "NewPassword")
	if _, err = cl.PasswordModify(req); err != nil {
		log.Fatalf("Password could not be changed: %v", err)
	}
}

func ExampleClientPasswordModifyGeneratedPassword() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	if err = cl.Bind("cn=user,dc=example,dc=com", "password"); err != nil {
		log.Fatal(err)
	}
	req := NewPasswordModifyRequest("", "OldPassword", "")
	res, err := cl.PasswordModify(req)
	if err != nil {
		log.Fatalf("Password could not be changed: %v", err)
	}
	log.Printf("Generated password: %s", res.GeneratedPassword)
}

func ExampleClientPasswordModifySetNewPassword() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	if err = cl.Bind("cn=user,dc=example,dc=com", "password"); err != nil {
		log.Fatal(err)
	}
	req := NewPasswordModifyRequest("", "OldPassword", "NewPassword")
	if _, err = cl.PasswordModify(req); err != nil {
		log.Fatalf("Password could not be changed: %v", err)
	}
}

func ExampleClientModify() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	// Add a description, and replace the mail attributes
	req := NewModifyRequest("cn=user,dc=example,dc=com", nil)
	req.Add("description", []string{"An example user"})
	req.Replace("mail", []string{"user@example.org"})
	if err = cl.Modify(req); err != nil {
		log.Fatal(err)
	}
}

// This example shows how a typical application can verify a login attempt
func ExampleClientUserAuthentication() {
	// The username and password we want to check
	username := "someuser"
	password := "userpassword"
	bindusername := "readonly"
	bindpassword := "password"
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	// Reconnect with TLS
	if err = cl.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		log.Fatal(err)
	}
	// First bind with a read only user
	if err = cl.Bind(bindusername, bindpassword); err != nil {
		log.Fatal(err)
	}
	// Search for the given username
	req := NewClientSearchRequest(
		"dc=example,dc=com",
		ScopeWholeSubtree, DerefAliasesNever, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", username),
		[]string{"dn"},
	)
	res, err := cl.Search(req)
	if err != nil {
		log.Fatal(err)
	}
	if len(res.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
	}
	userdn := res.Entries[0].DN
	// Bind as the user to verify their password
	if err = cl.Bind(userdn, password); err != nil {
		log.Fatal(err)
	}
	// Rebind as the read only user for any further queries
	if err = cl.Bind(bindusername, bindpassword); err != nil {
		log.Fatal(err)
	}
}

func ExampleClientBeheraPasswordPolicy() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	controls := []control.Control{
		control.NewBeheraPasswordPolicy(),
	}
	controls = append(controls)
	req := NewSimpleBindRequest("cn=admin,dc=example,dc=com", "password", controls...)
	res, err := cl.SimpleBind(req)
	if err != nil {
		log.Fatal(err)
	}
	ppolicyControl := control.Find(res.Controls, control.ControlBeheraPasswordPolicy.String())
	var ppolicy *control.BeheraPasswordPolicy
	if ppolicyControl != nil {
		ppolicy = ppolicyControl.(*control.BeheraPasswordPolicy)
	} else {
		log.Printf("ppolicyControl response not available.")
	}
	if ppolicy != nil {
		if ppolicy.Expire >= 0 {
			log.Printf("Password expires in %d seconds", ppolicy.Expire)
		} else if ppolicy.Grace >= 0 {
			log.Printf("Password expired, %d grace logins remain", ppolicy.Grace)
		}
	}
}

func ExampleClientVChuPasswordPolicy() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	req := NewSimpleBindRequest("cn=admin,dc=example,dc=com", "password", nil)
	res, err := cl.SimpleBind(req)
	passwordMustChangeControl := control.Find(res.Controls, control.ControlVChuPasswordMustChange.String())
	var passwordMustChange *control.VChuPasswordMustChange
	if passwordMustChangeControl != nil {
		passwordMustChange = passwordMustChangeControl.(*control.VChuPasswordMustChange)
	}
	if passwordMustChange != nil && passwordMustChange.MustChange {
		log.Printf("Password Must be changed.")
	}
	passwordWarningControl := control.Find(res.Controls, control.ControlVChuPasswordWarning.String())
	var passwordWarning *control.VChuPasswordWarning
	if passwordWarningControl != nil {
		passwordWarning = passwordWarningControl.(*control.VChuPasswordWarning)
	} else {
		log.Printf("ppolicyControl response not available.")
	}
	if err != nil {
		log.Fatal(err)
	}
	if passwordWarning != nil {
		if passwordWarning.Expire >= 0 {
			log.Printf("Password expires in %d seconds", passwordWarning.Expire)
		}
	}
}

// This example demonstrates how to use Paging to manually execute a
// paginated search request instead of using SearchWithPaging.
func ExampleClientPagingManualPaging() {
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	var pageSize uint32 = 32
	base := "dc=example,dc=com"
	filter := "(objectClass=group)"
	paging := control.NewPaging(pageSize)
	attributes := []string{}
	for {
		req := NewClientSearchRequest(base, ScopeWholeSubtree, DerefAliasesAlways, 0, 0, false, filter, attributes, paging)
		res, err := cl.Search(req)
		if err != nil {
			log.Fatalf("Failed to execute search request: %s", err.Error())
		}
		// [do something with the response entries]
		// In order to prepare the next request, we check if the response
		// contains another Paging object and a not-empty cookie and
		// copy that cookie into our pagingControl object:
		updatedControl := control.Find(res.Controls, control.ControlPaging.String())
		if ctrl, ok := updatedControl.(*control.Paging); ctrl != nil && ok && len(ctrl.Cookie) != 0 {
			paging.SetCookie(ctrl.Cookie)
			continue
		}
		// If no new paging information is available or the cookie is empty, we
		// are done with the pagination.
		break
	}
}

// This example demonstrates how to use EXTERNAL SASL with TLS client certificates.
func ExampleClientExternalBind() {
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
	cl, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer cl.Close()
	// reconnect using tls
	if err = cl.StartTLS(tlsConfig); err != nil {
		log.Fatal(err)
	}
	// sasl external bind
	if err = cl.ExternalBind(); err != nil {
		log.Fatal(err)
	}
	// Conduct ldap queries
}

// This example shows how to rename an entry without moving it
func ExampleClientModifyDNRenameNoMove() {
	cl, err := DialURL("ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s", err)
	}
	defer cl.Close()
	_, err = cl.SimpleBind(&ClientSimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s", err)
	}
	// just rename to uid=new,ou=people,dc=example,dc=org:
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "")
	if err = cl.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s", err)
	}
}

// This example shows how to rename an entry and moving it to a new base
func ExampleClientModifyDNRenameAndMove() {
	cl, err := DialURL("ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s", err)
	}
	defer cl.Close()
	_, err = cl.SimpleBind(&ClientSimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s", err)
	}
	// rename to uid=new,ou=people,dc=example,dc=org and move to ou=users,dc=example,dc=org ->
	// uid=new,ou=users,dc=example,dc=org
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "ou=users,dc=example,dc=org")
	if err = cl.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s", err)
	}
}

// This example shows how to move an entry to a new base without renaming the RDN
func ExampleClientModifyDNMoveOnly() {
	cl, err := DialURL("ldap://ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s", err)
	}
	defer cl.Close()
	_, err = cl.SimpleBind(&ClientSimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s", err)
	}
	// move to ou=users,dc=example,dc=org -> uid=user,ou=users,dc=example,dc=org
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=user", true, "ou=users,dc=example,dc=org")
	if err = cl.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s", err)
	}
}
