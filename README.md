[![Build Status](https://travis-ci.org/vjgorla/solr-ldap-plugin.svg?branch=master)](https://travis-ci.org/vjgorla/solr-ldap-plugin)

To use the plugin:
- Copy the jar file solr-ldap-plugin-0.0.1.jar into \server\solr-webapp\webapp\WEB-INF\lib . This has to be done on all solr nodes.
- Upload security.json that uses this plugin (actually two plugins) to zookeeper (see detailed plugin configuration below). Please note that config is not editable on the fly, so a node restart is required after every config change.
com.github.vjgorla.solr.security.LdapAuthenticationPlugin
com.github.vjgorla.solr.security.LdapRoleBasedAuthorizationPlugin
- LdapRoleBasedAuthorizationPlugin plugin is based on RuleBasedAuthorizationPlugin. It supports the same permission semantics.

An example security.json would be:

```
{
	"authentication": {
		"class": "com.github.vjgorla.solr.security.LdapAuthenticationPlugin",
		"blockUnknown": "true",
		"realm": "mysolr",
		"ldapCtxFactory": "com.sun.jndi.ldap.LdapCtxFactory",
		"ldapProviderUrl": "ldap://myldaphost:636",
		"ldapSecurityProtocol": "ssl",
		"ldapSecurityAuth": "simple",
		"ldapUserRootDn": "ou=people,dc=xyz,dc=com"
	},
	"authorization": {
		"class": "com.github.vjgorla.solr.security.LdapRoleBasedAuthorizationPlugin",
		"ldapCtxFactory": "com.sun.jndi.ldap.LdapCtxFactory",
		"ldapProviderUrl": "ldap://myldaphost:636",
		"ldapSecurityProtocol": "ssl",
		"ldapSecurityAuth": "simple",
		"ldapBindAccountDn": "cn=myserverbindaccount,ou=servers,dc=xyz,dc=com",
		"ldapBindAccountPassword": "myserverbindpwd",
		"ldapUserRootDn": "ou=people,dc=xyz,dc=com",
		"ldapGroupRootDn": "dc=xyz,dc=com",
		"permissions": [{
				"collection": null,
				"path": "/admin/collections",
				"params": {
					"action": ["LIST", "CLUSTERSTATUS", "CREATE"]
				},
				"role": "solr_admin",
				"index": 1
			}, {
				"name": "security-edit",
				"role": "solr_admin",
				"index": 2
			}, {
				"collection": "films",
				"name": "read",
				"role": "solr_user",
				"index": 3
			}, {
				"name": "update",
				"role": "solr_tech_support",
				"index": 4
			}, {
				"name": "read",
				"role": "solr_user",
				"index": 5
			}
		]
	}
}
```
