package com.github.vjgorla.solr.security;

import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapContext;

import org.apache.http.util.Args;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

	private static final Logger log = LoggerFactory.getLogger(Utils.class);
	
	private Utils() {
	}
	
	public static String getPluginConfigValue(Map<String, Object> pluginConfig, String configName) {
		String value = (String)pluginConfig.get(configName);
        Args.notBlank(value, "configName");
        return value;
	}

	public static Hashtable<String, String> getLdapEnv(Map<String, Object> pluginConfig) {
		Hashtable<String, String> ldapEnv = new Hashtable<>();
		ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, getPluginConfigValue(pluginConfig, "ldapCtxFactory"));
		ldapEnv.put(Context.PROVIDER_URL, getPluginConfigValue(pluginConfig, "ldapProviderUrl"));
		ldapEnv.put(Context.SECURITY_PROTOCOL, getPluginConfigValue(pluginConfig, "ldapSecurityProtocol"));
		ldapEnv.put(Context.SECURITY_AUTHENTICATION, getPluginConfigValue(pluginConfig, "ldapSecurityAuth"));
        return ldapEnv;
	}
	
	public static SearchControls newLdapSearchControls(String... attrs) {
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchControls.setTimeLimit(30000);
		searchControls.setReturningAttributes(attrs);
		return searchControls;
	}
	
	public static void closeLdapContext(LdapContext ctx) {
		if (ctx != null) {
			try { 
				ctx.close();
			} catch (Exception ex) {
				log.warn("Error closing LDAP context", ex);
			}
		}	
	}
}
