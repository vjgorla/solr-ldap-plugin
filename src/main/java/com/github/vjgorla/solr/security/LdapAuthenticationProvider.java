package com.github.vjgorla.solr.security;

import java.lang.invoke.MethodHandles;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.solr.common.util.ValidatingJsonMap;
import org.apache.solr.security.BasicAuthPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class LdapAuthenticationProvider implements BasicAuthPlugin.AuthenticationProvider {
	
	private Hashtable<String, String> ldapEnv;
	private String ldapUserRootDn;
	private String realm;
	private Map<String, String> promptHeader;

	private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	@Override
	public void init(Map<String, Object> pluginConfig) {
		this.ldapEnv = Utils.getLdapEnv(pluginConfig);
		this.ldapUserRootDn = Utils.getPluginConfigValue(pluginConfig, "ldapUserRootDn");
		if (pluginConfig.get("realm") != null) { 
			this.realm = (String) pluginConfig.get("realm"); 
		} else { 
			this.realm = "solr";
		}
		this.promptHeader = Collections.unmodifiableMap(Collections.singletonMap("WWW-Authenticate", "Basic realm=\"" + realm + "\""));
	}

  public boolean authenticate(String username, String password) {
		log.info("Authenticating user {} using LDAP", username);
		
		LdapContext ctx = null;
		try {
			Hashtable<String, String> authLdapEnv = new Hashtable<>(this.ldapEnv);
			authLdapEnv.put(Context.SECURITY_PRINCIPAL, "uid=" + username + "," + this.ldapUserRootDn);
			authLdapEnv.put(Context.SECURITY_CREDENTIALS, password);
			ctx = new InitialLdapContext(authLdapEnv, null);
		} catch (Exception ex) {
			log.info("Authentication failed for user {} with error {}", username, ex.getLocalizedMessage());
			return false;
		} finally {
			Utils.closeLdapContext(ctx);
		}
		log.info("Authentication successful for user {}", username);
		return true;
  }

  @Override
  public Map<String, String> getPromptHeaders() {
    return promptHeader;
  }

  @Override
  public ValidatingJsonMap getSpec() {
    return org.apache.solr.common.util.Utils.getSpec("cluster.security.BasicAuth.Commands").getSpec();
  }
}

