package com.github.vjgorla.solr.security;

import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Looks up roles in LDAP
 * 
 * @author Vijaya Gorla
 */
public class LdapRoleLookupService implements LdapRoleBasedAuthorizationPlugin.RoleLookupService {

	private static final Logger log = LoggerFactory.getLogger(LdapRoleLookupService.class);

	private Hashtable<String, String> ldapEnv;
	private String ldapUserRootDn;
	private String ldapGroupRootDn;

	@Override
	public void init(Map<String, Object> pluginConfig) {
		this.ldapEnv = Utils.getLdapEnv(pluginConfig);
		this.ldapEnv.put(Context.SECURITY_PRINCIPAL, Utils.getPluginConfigValue(pluginConfig, "ldapBindAccountDn"));
		this.ldapEnv.put(Context.SECURITY_CREDENTIALS, Utils.getPluginConfigValue(pluginConfig, "ldapBindAccountPassword"));
		this.ldapUserRootDn = Utils.getPluginConfigValue(pluginConfig, "ldapUserRootDn");
		this.ldapGroupRootDn = Utils.getPluginConfigValue(pluginConfig, "ldapGroupRootDn");
	}
	
	@Override
	public Set<String> getRoles(String username) {
		log.info("Looking up roles for user {} in LDAP", username);
		
        LdapContext ctx = null;
		try {
	        ctx = new InitialLdapContext(this.ldapEnv, null);
			ctx.setRequestControls(null);
			return getUserGroups(ctx, username);
		} catch (Exception ex) {
			log.warn("Error looking up roles in LDAP", ex);
			return Collections.emptySet();
		} finally {
			Utils.closeLdapContext(ctx);
		}
	}
	
	private Set<String> getUserGroups(LdapContext ctx, String username) throws NamingException {
		NamingEnumeration<SearchResult> namingEnum 
		= ctx.search(ldapGroupRootDn, 
					"(&(member=uid=" + username + "," + this.ldapUserRootDn + ")(objectClass=groupOfNames))", 
					Utils.newLdapSearchControls("cn"));
		Set<String> groups = new HashSet<>();
		while (namingEnum.hasMore()) {
			SearchResult result = (SearchResult)namingEnum.next();
			groups.add((String)result.getAttributes().get("cn").get());
		}
		namingEnum.close();
		return groups;
	}
}
