package com.github.vjgorla.solr.security;

import java.util.Map;

import org.apache.solr.security.BasicAuthPlugin;

/**
 * 
 * @author Vijaya Gorla
 */
public class LdapAuthenticationPlugin extends BasicAuthPlugin {

	protected AuthenticationProvider getAuthenticationProvider(Map<String, Object> pluginConfig) {
		LdapAuthenticationProvider provider = new LdapAuthenticationProvider();
	    provider.init(pluginConfig);
	    return provider;
	}
}
