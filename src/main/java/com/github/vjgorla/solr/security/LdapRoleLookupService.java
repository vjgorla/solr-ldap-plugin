package com.github.vjgorla.solr.security;

import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.http.util.Args;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Looks up roles in LDAP
 * 
 * @author Vijay Gorla
 */
public class LdapRoleLookupService implements PreAuthRuleBasedAuthorizationPlugin.RoleLookupService {

	private static final Logger log = LoggerFactory.getLogger(LdapRoleLookupService.class);

	private Hashtable<String, String> ldapEnv;
	private String ldapUserRootDn;
	private String ldapGroupRootDn;
	private String ldapGroupQueryPredicate;

	@Override
	public void init(Map<String, Object> pluginConfig) {

		Hashtable<String, String> ldapEnv = new Hashtable<String, String>();
		ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, getConfig(pluginConfig, "ldapCtxFactory"));
		ldapEnv.put(Context.PROVIDER_URL, getConfig(pluginConfig, "ldapProviderUrl"));
		ldapEnv.put(Context.SECURITY_PROTOCOL, getConfig(pluginConfig, "ldapSecurityProtocol"));
		ldapEnv.put(Context.SECURITY_AUTHENTICATION, getConfig(pluginConfig, "ldapSecurityAuth"));
		ldapEnv.put(Context.SECURITY_PRINCIPAL, getConfig(pluginConfig, "ldapBindAccountDn"));
		ldapEnv.put(Context.SECURITY_CREDENTIALS, getConfig(pluginConfig, "ldapBindAccountPassword"));
        
		this.ldapEnv = ldapEnv;
		
		ldapUserRootDn = getConfig(pluginConfig, "ldapUserRootDn");
		ldapGroupRootDn = getConfig(pluginConfig, "ldapGroupRootDn");
		ldapGroupQueryPredicate = getConfig(pluginConfig, "ldapGroupQueryPredicate");
	}
	
	@Override
	public Set<String> getRoles(String username) {
		log.info("Looking up roles for user {} in LDAP", username);
		
        LdapContext ctx = null;
		try {
	        ctx = new InitialLdapContext(ldapEnv, null);
			ctx.setRequestControls(null);
			String usercn = getUserCn(ctx, username);
			if (usercn == null) {
				return Collections.emptySet();
			}
			Set<String> groups = getUserGroups(ctx, username);
			return groups;
		} catch (Exception ex) {
			log.warn("Error looking up roles in LDAP", ex);
			return Collections.emptySet();
		} finally {
			if (ctx != null) {
				try { 
					ctx.close();
				} catch (Exception ex) {
					log.warn("Error closing LDAP context", ex);
				}
			}
		}
	}
	
	private String getUserCn(LdapContext ctx, String username) throws NamingException {
		try {
			NamingEnumeration<SearchResult> namingEnum 
				= ctx.search(getUserDn(username), "(objectclass=person)", getSimpleSearchControls());
			String cn = null;
			while (namingEnum.hasMore()) {
				SearchResult result = (SearchResult)namingEnum.next();
				cn = (String)result.getAttributes().get("cn").get();
			}
			namingEnum.close();
			return cn;
		} catch (NameNotFoundException nnfe) {
			return null;
		}
	}
	
	private Set<String> getUserGroups(LdapContext ctx, String username) throws NamingException {
		NamingEnumeration<SearchResult> namingEnum 
		= ctx.search(ldapGroupRootDn, 
					"(&(member=" + getUserDn(username) + ")(objectClass=groupOfNames)" + ldapGroupQueryPredicate + ")", 
					getSimpleSearchControls());
		Set<String> groups = new HashSet<>();
		while (namingEnum.hasMore()) {
			SearchResult result = (SearchResult)namingEnum.next();
			groups.add((String)result.getAttributes().get("cn").get());
		}
		namingEnum.close();
		return groups;
	}
	
	private static String getConfig(Map<String, Object> pluginConfig, String configName) {
		String value = (String)pluginConfig.get(configName);
        Args.notBlank(value, "configName");
        return value;
	}

	private String getUserDn(String username) {
		return "uid=" + username + "," + ldapUserRootDn;
	}

	private static SearchControls getSimpleSearchControls() {
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchControls.setTimeLimit(30000);
		String[] attrIDs = {"cn"};
		searchControls.setReturningAttributes(attrIDs);
		return searchControls;
	}
}
