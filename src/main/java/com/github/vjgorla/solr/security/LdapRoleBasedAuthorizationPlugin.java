package com.github.vjgorla.solr.security;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.http.util.TextUtils;
import org.apache.solr.common.SolrException;
import org.apache.solr.common.SpecProvider;
import org.apache.solr.common.util.Utils;
import org.apache.solr.common.util.ValidatingJsonMap;
import org.apache.solr.security.AuthorizationContext;
import org.apache.solr.security.AuthorizationPlugin;
import org.apache.solr.security.AuthorizationResponse;
import org.apache.solr.security.ConfigEditablePlugin;
import org.apache.solr.security.PermissionNameProvider;
import org.apache.solr.common.util.CommandOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableSet;

import static java.util.Arrays.asList;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static java.util.Collections.unmodifiableMap;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;
import static org.apache.solr.common.params.CommonParams.NAME;
import static org.apache.solr.common.util.Utils.getDeepCopy;
import static org.apache.solr.handler.admin.SecurityConfHandler.getListValue;

/**
 * Modified version of {@link org.apache.solr.security.RuleBasedAuthorizationPlugin}. 
 * 
 * Instead of getting the user roles from the "user-role" mapping in security config, this implementation 
 * fetches the roles from LDAP.  
 *   
 * @author Vijaya Gorla
 */
public class LdapRoleBasedAuthorizationPlugin implements AuthorizationPlugin, ConfigEditablePlugin, SpecProvider {
  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private final Map<String, WildCardSupportMap> mapping = new HashMap<>();
  private final List<Permission> permissions = new ArrayList<>();
  private RoleLookupService roleLookupService;

  public interface RoleLookupService {
	void init(Map<String, Object> pluginConfig);
	Set<String> getRoles(String username);
  }

  @SuppressWarnings("serial")
  private static class WildCardSupportMap extends HashMap<String, List<Permission>> {
    final Set<String> wildcardPrefixes = new HashSet<>();

    @Override
    public List<Permission> put(String key, List<Permission> value) {
      if (key != null && key.endsWith("/*")) {
        key = key.substring(0, key.length() - 2);
        wildcardPrefixes.add(key);
      }
      return super.put(key, value);
    }

    @Override
    public List<Permission> get(Object key) {
      List<Permission> result = super.get(key);
      if (key == null || result != null) return result;
      if (!wildcardPrefixes.isEmpty()) {
        for (String s : wildcardPrefixes) {
          if (key.toString().startsWith(s)) {
            List<Permission> l = super.get(s);
            if (l != null) {
              result = result == null ? new ArrayList<>() : new ArrayList<>(result);
              result.addAll(l);
            }
          }
        }
      }
      return result;
    }
  }

  @Override
  public AuthorizationResponse authorize(AuthorizationContext context) {
    Principal principal = context.getUserPrincipal();
    if (principal == null || TextUtils.isBlank(principal.getName())) {
        log.info("Request has come without principal, rejecting.");
        return MatchStatus.FORBIDDEN.rsp;
    }
    Set<String> userRoles = roleLookupService.getRoles(principal.getName());
    List<AuthorizationContext.CollectionRequest> collectionRequests = context.getCollectionRequests();
    if (context.getRequestType() == AuthorizationContext.RequestType.ADMIN) {
      MatchStatus flag = checkCollPerm(mapping.get(null), context, userRoles);
      return flag.rsp;
    }

    for (AuthorizationContext.CollectionRequest collreq : collectionRequests) {
      //check permissions for each collection
      MatchStatus flag = checkCollPerm(mapping.get(collreq.collectionName), context, userRoles);
      if (flag != MatchStatus.NO_PERMISSIONS_FOUND) return flag.rsp;
    }
    //check wildcard (all=*) permissions.
    MatchStatus flag = checkCollPerm(mapping.get("*"), context, userRoles);
    return flag.rsp;
  }

  private MatchStatus checkCollPerm(Map<String, List<Permission>> pathVsPerms,
                                    AuthorizationContext context,
                                    Set<String> userRoles) {
    if (pathVsPerms == null) return MatchStatus.NO_PERMISSIONS_FOUND;

    String path = context.getResource();
    MatchStatus flag = checkPathPerm(pathVsPerms.get(path), context, userRoles);
    if (flag != MatchStatus.NO_PERMISSIONS_FOUND) return flag;
    return checkPathPerm(pathVsPerms.get(null), context, userRoles);
  }

  private MatchStatus checkPathPerm(List<Permission> permissions, AuthorizationContext context, Set<String> userRoles) {
    if (permissions == null || permissions.isEmpty()) return MatchStatus.NO_PERMISSIONS_FOUND;
    loopPermissions:
    for (int i = 0; i < permissions.size(); i++) {
      Permission permission = permissions.get(i);
      if (PermissionNameProvider.values.containsKey(permission.name)) {
        if (context.getHandler() instanceof PermissionNameProvider) {
          PermissionNameProvider handler = (PermissionNameProvider) context.getHandler();
          PermissionNameProvider.Name permissionName = handler.getPermissionName(context);
          String permissionNameName = null;
      	  try {
      		permissionNameName = (String)FieldUtils.readField(permissionName, "name", true);
		  } catch (IllegalAccessException ex) {
			throw new RuntimeException(ex);
		  }
          if (permissionName == null || !permission.name.equals(permissionNameName)) {
            continue;
          }
        } else {
          //all is special. it can match any
          if(permission.wellknownName != PermissionNameProvider.Name.ALL) continue;
        }
      } else {
        if (permission.method != null && !permission.method.contains(context.getHttpMethod())) {
          //this permissions HTTP method does not match this rule. try other rules
          continue;
        }
        if (permission.params != null) {
          for (Map.Entry<String, Function<String[], Boolean>> e : permission.params.entrySet()) {
            String[] paramVal = context.getParams().getParams(e.getKey());
            if(!e.getValue().apply(paramVal)) continue loopPermissions;
          }
        }
      }
      if (permission.role == null) {
        //no role is assigned permission.That means everybody is allowed to access
        return MatchStatus.PERMITTED;
      }
      if (permission.role.contains("*")) {
        return MatchStatus.PERMITTED;
      }

      for (String role : permission.role) {
        if (userRoles != null && userRoles.contains(role)) return MatchStatus.PERMITTED;
      }
      log.info("This resource is configured to have a permission {}, however user has roles {}", permission, userRoles);
      return MatchStatus.FORBIDDEN;
    }
    log.debug("No permissions configured for the resource {} . So allowed to access", context.getResource());
    return MatchStatus.NO_PERMISSIONS_FOUND;
  }

  @SuppressWarnings({ "unchecked", "rawtypes" })
  @Override
  public void init(Map<String, Object> initInfo) {
    mapping.put(null, new WildCardSupportMap());
    List<Map> perms = getListValue(initInfo, "permissions");
    for (Map o : perms) {
      Permission p;
      try {
        p = Permission.load(o);
      } catch (Exception exp) {
        log.error("Invalid permission ", exp);
        continue;
      }
      permissions.add(p);
      add2Mapping(p);
    }
    roleLookupService = new CachingRoleLookupService(new LdapRoleLookupService());
    roleLookupService.init(initInfo);
  }

  //this is to do optimized lookup of permissions for a given collection/path
  private void add2Mapping(Permission permission) {
    for (String c : permission.collections) {
      WildCardSupportMap m = mapping.get(c);
      if (m == null) mapping.put(c, m = new WildCardSupportMap());
      for (String path : permission.path) {
        List<Permission> perms = m.get(path);
        if (perms == null) m.put(path, perms = new ArrayList<>());
        perms.add(permission);
      }
    }
  }

  @Override
  public void close() throws IOException { }

  enum MatchStatus {
    USER_REQUIRED(AuthorizationResponse.PROMPT),
    NO_PERMISSIONS_FOUND(AuthorizationResponse.OK),
    PERMITTED(AuthorizationResponse.OK),
    FORBIDDEN(AuthorizationResponse.FORBIDDEN);

    final AuthorizationResponse rsp;

    MatchStatus(AuthorizationResponse rsp) {
      this.rsp = rsp;
    }
  }

  @Override
  public Map<String, Object> edit(Map<String, Object> latestConf, List<CommandOperation> commands) {
    for (CommandOperation op : commands) {
      AutorizationEditOperation operation = ops.get(op.name);
      if (operation == null) {
        op.unknownOperation();
        return null;
      }
      latestConf = operation.edit(latestConf, op);
      if (latestConf == null) return null;

    }
    return latestConf;
  }

  private static final Map<String, AutorizationEditOperation> ops = unmodifiableMap(asList(AutorizationEditOperation.values()).stream().collect(toMap(AutorizationEditOperation::getOperationName, identity())));

  @Override
  public ValidatingJsonMap getSpec() {
    return Utils.getSpec("cluster.security.RuleBasedAuthorization").getSpec();

  }
  
  private static enum AutorizationEditOperation {
	  SET_PERMISSION("set-permission") {
		@Override
	    @SuppressWarnings({ "unchecked", "rawtypes" })
	    public Map<String, Object> edit(Map<String, Object> latestConf, CommandOperation op) {
	      Integer index = op.getInt("index", null);
	      Integer beforeIdx = op.getInt("before",null);
	      Map<String, Object> dataMap = op.getDataMap();
	      if (op.hasError()) return null;
	      dataMap = getDeepCopy(dataMap, 3);
	      dataMap.remove("before");
	      if (beforeIdx != null && index != null) {
	        op.addError("Cannot use 'index' and 'before together ");
	        return null;
	      }

	      for (String key : dataMap.keySet()) {
	        if (!Permission.knownKeys.contains(key)) op.addError("Unknown key, " + key);
	      }
	      try {
	        Permission.load(dataMap);
	      } catch (Exception e) {
	        op.addError(e.getMessage());
	        return null;
	      }
	      if(op.hasError()) return null;
	      List<Map> permissions = getListValue(latestConf, "permissions");
	      setIndex(permissions);
	      List<Map> permissionsCopy = new ArrayList<>();
	      boolean beforeSatisfied = beforeIdx == null;
	      boolean indexSatisfied = index == null;
	      for (int i = 0; i < permissions.size(); i++) {
	        Map perm = permissions.get(i);
	        Integer thisIdx = (Integer) perm.get("index");
	        if (thisIdx.equals(beforeIdx)) {
	          beforeSatisfied = true;
	          permissionsCopy.add(dataMap);
	          permissionsCopy.add(perm);
	        } else if (thisIdx.equals(index)) {
	          //overwriting an existing one
	          indexSatisfied = true;
	          permissionsCopy.add(dataMap);
	        } else {
	          permissionsCopy.add(perm);
	        }
	      }

	      if (!beforeSatisfied) {
	        op.addError("Invalid 'before' :" + beforeIdx);
	        return null;
	      }
	      if (!indexSatisfied) {
	        op.addError("Invalid 'index' :" + index);
	        return null;
	      }

	      if (!permissionsCopy.contains(dataMap)) permissionsCopy.add(dataMap);
	      latestConf.put("permissions", permissionsCopy);
	      setIndex(permissionsCopy);
	      return latestConf;
	    }

	  },
	  UPDATE_PERMISSION("update-permission") {
		@Override
	    @SuppressWarnings({ "unchecked", "rawtypes" })
	    public Map<String, Object> edit(Map<String, Object> latestConf, CommandOperation op) {
	      Integer index = op.getInt("index");
	      if (op.hasError()) return null;
	      List<Map> permissions = (List<Map>) getListValue(latestConf, "permissions");
	      setIndex(permissions);
	      for (Map permission : permissions) {
	        if (index.equals(permission.get("index"))) {
	          LinkedHashMap copy = new LinkedHashMap<>(permission);
	          copy.putAll(op.getDataMap());
	          op.setCommandData(copy);
	          return SET_PERMISSION.edit(latestConf, op);
	        }
	      }
	      op.addError("No such permission " + name);
	      return null;
	    }
	  },
	  DELETE_PERMISSION("delete-permission") {
		@Override
	    @SuppressWarnings({ "unchecked", "rawtypes" })
	    public Map<String, Object> edit(Map<String, Object> latestConf, CommandOperation op) {
	      Integer id = op.getInt("");
	      if(op.hasError()) return null;
	      List<Map> p = getListValue(latestConf, "permissions");
	      setIndex(p);
	      List<Map> c = p.stream().filter(map -> !id.equals(map.get("index"))).collect(Collectors.toList());
	      if(c.size() == p.size()){
	        op.addError("No such index :"+ id);
	        return null;
	      }
	      latestConf.put("permissions", c);
	      return latestConf;
	    }
	  };

	  public abstract Map<String, Object> edit(Map<String, Object> latestConf, CommandOperation op);

	  public final String name;

	  public String getOperationName() {
	    return name;
	  }

	  AutorizationEditOperation(String s) {
	    this.name = s;
	  }

	  @SuppressWarnings("unused")
	  public static AutorizationEditOperation get(String name) {
	    for (AutorizationEditOperation o : values()) if (o.name.equals(name)) return o;
	    return null;
	  }

	  @SuppressWarnings({ "rawtypes", "unchecked" })
	  static void setIndex(List<Map> permissionsCopy) {
	    AtomicInteger counter = new AtomicInteger(0);
	    permissionsCopy.stream().forEach(map -> map.put("index", counter.incrementAndGet()));
	  }
  }
  
  private static class Permission {
	  String name;
	  Set<String> path, role, collections, method;
	  Map<String, Function<String[], Boolean>> params;
	  PermissionNameProvider.Name wellknownName;
	  @SuppressWarnings("rawtypes")
	  Map originalConfig;

	  private Permission() {
	  }

	  @SuppressWarnings({ "unchecked", "rawtypes" })
	  static Permission load(Map m) {
	    Permission p = new Permission();
	    p.originalConfig = new LinkedHashMap<>(m);
	    String name = (String) m.get(NAME);
	    if (!m.containsKey("role")) throw new SolrException(SolrException.ErrorCode.BAD_REQUEST, "role not specified");
	    p.role = readValueAsSet(m, "role");
	    if (PermissionNameProvider.Name.get(name)!= null) {
	      p.wellknownName = PermissionNameProvider.Name.get(name);
	      HashSet<String> disAllowed = new HashSet<>(knownKeys);
	      disAllowed.remove("role");//these are the only
	      disAllowed.remove(NAME);//allowed keys for well-known permissions
	      disAllowed.remove("collection");//allowed keys for well-known permissions
	      disAllowed.remove("index");
	      for (String s : disAllowed) {
	        if (m.containsKey(s))
	          throw new SolrException(SolrException.ErrorCode.BAD_REQUEST, s + " is not a valid key for the permission : " + name);
	      }

	    }
	    p.name = name;
	    p.path = readSetSmart(name, m, "path");
	    p.collections = readSetSmart(name, m, "collection");
	    p.method = readSetSmart(name, m, "method");
	    Map<String, Object> paramRules = (Map<String, Object>) m.get("params");
	    if (paramRules != null) {
	      p.params = new LinkedHashMap<>();
	      for (Map.Entry<String, Object> e : paramRules.entrySet()) {
	        if (e.getValue() == null) {
	          p.params.put(e.getKey(), (String[] val) -> val == null);
	        } else {
	          List<String> patternStrs = e.getValue() instanceof List ?
	              (List) e.getValue() :
	              singletonList(e.getValue().toString());
	          List patterns = patternStrs.stream()
	              .map(it -> it.startsWith("REGEX:") ?
	                  Pattern.compile(String.valueOf(it.substring("REGEX:".length())))
	                  : it)
	              .collect(Collectors.toList());
	          p.params.put(e.getKey(), val -> {
	            if (val == null) return false;
	            for (Object pattern : patterns) {
	              for (String s : val) {
	                if (pattern instanceof String) {
	                  if (pattern.equals(s)) return true;
	                } else if (pattern instanceof Pattern) {
	                  if (((Pattern) pattern).matcher(s).find()) return true;
	                }
	              }
	            }
	            return false;
	          });
	        }
	      }
	    }
	    return p;
	  }

	  /**
	   * This checks for the defaults available other rules for the keys
	   */
	  @SuppressWarnings({ "rawtypes", "unchecked" })
	  private static Set<String> readSetSmart(String permissionName, Map m, String key) {
	    if(PermissionNameProvider.values.containsKey(permissionName) && !m.containsKey(key) && "collection".equals(key)) {
	    	PermissionNameProvider.Name permName = PermissionNameProvider.Name.get(permissionName);
	    	try {
				return (Set<String>)FieldUtils.readField(permName, "collName", true);
			} catch (IllegalAccessException ex) {
				throw new RuntimeException(ex);
			}
	    }
	    Set<String> set = readValueAsSet(m, key);
	    if ("method".equals(key)) {
	      if (set != null) {
	        for (String s : set) if (!HTTP_METHODS.contains(s)) return null;
	      }
	      return set;
	    }
	    return set == null ? singleton(null) : set;
	  }
	  /**
	   * read a key value as a set. if the value is a single string ,
	   * return a singleton set
	   *
	   * @param m   the map from which to lookup
	   * @param key the key with which to do lookup
	   */
	  @SuppressWarnings("rawtypes")
	  static Set<String> readValueAsSet(Map m, String key) {
	    Set<String> result = new HashSet<>();
	    Object val = m.get(key);
	    if (val == null) {
	      if("collection".equals(key)) {
	        //for collection collection: null means a core admin/ collection admin request
	        // otherwise it means a request where collection name is ignored
	        return m.containsKey(key) ? singleton(null) : singleton("*");
	      }
	      return null;
	    }
	    if (val instanceof Collection) {
	      Collection list = (Collection) val;
	      for (Object o : list) result.add(String.valueOf(o));
	    } else if (val instanceof String) {
	      result.add((String) val);
	    } else {
	      throw new RuntimeException("Bad value for : " + key);
	    }
	    return result.isEmpty() ? null : Collections.unmodifiableSet(result);
	  }

	  @Override
	  public String toString() {
	   return Utils.toJSONString(originalConfig);
	  }

	  static final Set<String> knownKeys = ImmutableSet.of("collection", "role", "params", "path", "method", NAME,"index");
	  public static final Set<String> HTTP_METHODS = ImmutableSet.of("GET", "POST", "DELETE", "PUT", "HEAD");
  }
}
