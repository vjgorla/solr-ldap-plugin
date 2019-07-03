package com.github.vjgorla.solr.security;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

/**
 * A caching wrapper for a real RoleLookupService
 * 
 * @author Vijay Gorla
 */
public class CachingRoleLookupService implements PreAuthRuleBasedAuthorizationPlugin.RoleLookupService {

	private static final Logger log = LoggerFactory.getLogger(CachingRoleLookupService.class);
	private static final long DEFAULT_ROLE_CACHE_MAX_SIZE = 1000;
	private static final long DEFAULT_ROLE_CACHE_TTL_MINUTES = 60;

	private final PreAuthRuleBasedAuthorizationPlugin.RoleLookupService target;
	private LoadingCache<String, Set<String>> cache;

	public CachingRoleLookupService(PreAuthRuleBasedAuthorizationPlugin.RoleLookupService target) {
		this.target = target;
	}
	
	@Override
	public void init(Map<String, Object> pluginConfig) {
		target.init(pluginConfig);
		Long ldapCacheMaximumSize = (Long)pluginConfig.get("roleCacheMaximumSize");
	    if (ldapCacheMaximumSize == null) {
	    	ldapCacheMaximumSize = DEFAULT_ROLE_CACHE_MAX_SIZE;
	    }
		Long roleCacheTtlMinutes = (Long)pluginConfig.get("roleCacheTtlMinutes");
	    if (roleCacheTtlMinutes == null) {
	    	roleCacheTtlMinutes = DEFAULT_ROLE_CACHE_TTL_MINUTES;
	    }
    	cache = CacheBuilder.newBuilder()
			       .maximumSize(ldapCacheMaximumSize)
			       .expireAfterWrite(roleCacheTtlMinutes, TimeUnit.MINUTES)
			       .build(new CacheLoader<String, Set<String>>() {
			             public Set<String> load(String key) {
			               return target.getRoles(key);
			             }
		           });
	}
	
	@Override
	public Set<String> getRoles(String username) {
		try {
			Set<String> roles = cache.get(username);
			log.info("User {} has roles {}", username, roles);
			return roles;
		} catch(Exception ex) {
			log.warn("Error looking up roles in cache", ex);
			return Collections.emptySet();
		}
	}
}
