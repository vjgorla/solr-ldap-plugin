package com.github.vjgorla.solr.security;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.auth.BasicUserPrincipal;
import org.apache.http.util.TextUtils;
import org.apache.solr.security.AuthenticationPlugin;

/**
 * To be used where authentication is handled by an upstream system, which is usually the case where authenticating
 * reverse proxies such as webseal are used in front of solr. 
 * 
 * Sets up the user principal using the user name provided in the request header so that plugins in the filter chain
 * can use it to apply role based security based on the principal.
 * 
 * If this plugin is used, Solr should be locked down to requests coming through the reverse proxy (either using SSL
 * mutual authentication or IP restriction) because of the mutual trust required.
 * 
 * @author Vijay Gorla
 */
public class PreAuthAuthenticationPlugin extends AuthenticationPlugin {

	private String authHeaderField;

	@Override
	public void init(Map<String, Object> pluginConfig) {
		authHeaderField = (String)pluginConfig.get("authHeaderField");
	}

	@Override
	public boolean doAuthenticate(ServletRequest servletRequest, 
			                      ServletResponse servletResponse,
			                      FilterChain filterChain) throws Exception {

		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		final String username = request.getHeader(authHeaderField);
		if (TextUtils.isBlank(username)) {
			response.sendError(403, "Authentication required");
			return false;
		} else {
			HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request) {
				@Override
				public Principal getUserPrincipal() {
					return new BasicUserPrincipal(username);
				}
			};
			filterChain.doFilter(wrapper, response);
			return true;
		}
	}

	@Override
	public void close() throws IOException {
	}
}
