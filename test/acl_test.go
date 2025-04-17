package test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kurtie/gockham"
	"gotest.tools/v3/assert"
)

func TestAcl(t *testing.T) {
	err := gockham.InitAcl("acl.json")
	assert.NilError(t, err, "ACL initialization failed")

	gockham.Request.Auth.Subject = "alice"
	gockham.Request.Auth.Claims = jwt.MapClaims{"roles": []any{"admin"}}

	assert.Equal(t, gockham.AuthAclClosure("read"), true, "Alice should have read permission")
	assert.Equal(t, gockham.AuthAclClosure("whatever"), true, "Alice should have whatever permission")

	gockham.Request.Auth.Subject = "bob"
	gockham.Request.Auth.Claims = jwt.MapClaims{"roles": []any{"writer"}}
	assert.Equal(t, gockham.AuthAclClosure("write"), true, "Bob should have write permission")
	assert.Equal(t, gockham.AuthAclClosure("admin"), false, "Bob should not have admin permission")

	gockham.Request.Auth.Subject = "charlie"
	gockham.Request.Auth.Claims = jwt.MapClaims{"roles": []any{"reader"}}
	assert.Equal(t, gockham.AuthAclClosure("read"), true, "Charlie should have read permission")
	assert.Equal(t, gockham.AuthAclClosure("guest"), true, "Charlie should have guest permission")
	assert.Equal(t, gockham.AuthAclClosure("write"), false, "Charlie should not have write permission")
	assert.Equal(t, gockham.AuthAclClosure("admin"), false, "Charlie should not have admin permission")

	gockham.Request.Auth.Subject = "dave"
	gockham.Request.Auth.Claims = jwt.MapClaims{"roles": []any{"guest"}}
	assert.Equal(t, gockham.AuthAclClosure("read"), false, "Dave should not have read permission")
	assert.Equal(t, gockham.AuthAclClosure("guest"), true, "Dave should have guest permission")
	assert.Equal(t, gockham.AuthAclClosure("write"), false, "Dave should not have write permission")
	assert.Equal(t, gockham.AuthAclClosure("admin"), false, "Dave should not have admin permission")

	gockham.Request.Auth.Subject = "eve"
	gockham.Request.Auth.Claims = jwt.MapClaims{"roles": []any{"finance", "guest"}}
	assert.Equal(t, gockham.AuthAclClosure("read"), false, "Eve should not have read permission")
	assert.Equal(t, gockham.AuthAclClosure("guest"), true, "Eve should have guest permission")
	assert.Equal(t, gockham.AuthAclClosure("write"), false, "Eve should not have write permission")
	assert.Equal(t, gockham.AuthAclClosure("admin"), false, "Eve should not have admin permission")
	assert.Equal(t, gockham.AuthAclClosure("finance.read"), true, "Eve should have guest permission")
	assert.Equal(t, gockham.AuthAclClosure("finance.write"), true, "Eve should have guest permission")
}

// func TestAclRoleGrants(t *testing.T) {
// 	err := gockham.InitAcl("acl.json")
// 	assert.NilError(t, err, "ACL initialization failed")

// 	grants := gockham.AclRoleGrants("finance")
// 	fmt.Printf("grants: %v\n", grants)
// 	assert.Equal(t, len(grants), 2, "Eve should have 2 grants")
// }

func TestExtraRule(t *testing.T) {
	err := gockham.InitAcl("acl.json")
	assert.NilError(t, err, "ACL initialization failed")
	gockham.AclExtraRule("finance.read", "external", func() bool { return false })

	gockham.Request.Auth.Subject = "frank"
	gockham.Request.Auth.Claims = jwt.MapClaims{"roles": []any{"finance"}}
	assert.Equal(t, gockham.AuthAclClosure("finance.write"), true, "Frank should have write permission")

	gockham.Request.Auth.Subject = "gemma"
	gockham.Request.Auth.Claims = jwt.MapClaims{"roles": []any{"external"}}
	assert.Equal(t, gockham.AuthAclClosure("finance.read"), false, "Gemma should not have read permission")

}
