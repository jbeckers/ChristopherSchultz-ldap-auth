package net.christopherschultz.mirth.plugins.auth.ldap;

import com.kaurpalang.mirth.annotationsplugin.annotation.MirthServerClass;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStatus.Status;
import com.mirth.connect.model.User;
import com.mirth.connect.plugins.AuthorizationPlugin;
import com.mirth.connect.plugins.ServicePlugin;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.UserController;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import lombok.extern.slf4j.Slf4j;


/**
 * An LDAP authenticator for Mirth Connect.
 *
 */
@SuppressWarnings({"AssignmentToNull", "ReturnOfNull", "ParameterNameDiffersFromOverriddenParameter", "ObjectAllocationInLoop"})
@MirthServerClass
@Slf4j
public class LDAPAuthenticatorPlugin
        implements AuthorizationPlugin, ServicePlugin {
    private static final String DEFAULT_CONTEXT_FACTORY_CLASS_NAME = "com.sun.jndi.ldap.LdapCtxFactory";
    private static final int DEFAULT_RETRIES = 3;
    private static final int MAX_RETRIES = 100;
    private static final long DEFAULT_RETRY_INTERVAL = 1000;
    private static final long MAX_RETRY_INTERVAL = 10000;

    private String contextFactoryClassName;
    private String url;
    private String userDNTemplate;
    private String baseDN;
    private String groupFilterTemplate;
    private int retries;
    private long retryInterval;
    private boolean fallbackToLocalAuthentication = false;
    private Map<String, String> usernameMap;
    private String usernameTemplate;

    @Override
    public String getPluginPointName() {
        return "LDAP-Authenticator";
    }

    @Override
    public Properties getDefaultProperties() {
        if (log.isDebugEnabled()) {
            log.debug("getDefaultProperties called");
        }
        return new Properties();
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return null;
    }

    @Override
    public void init(final Properties properties) {
        Properties localProperties = new Properties(properties);
        // Load the configuration from ldap.properties and return it.
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("ldap.properties")) {
            if (in == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No local ldap.properties found; using database configuration with {} items", properties.size());
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Found local ldap.properties file; merging with database configuration");
                }
                localProperties.load(in);
                if (log.isDebugEnabled()) {
                    log.debug("Loaded {} items from local ldap.properties; merged with {} items from database", localProperties.size(), properties.size());
                }
            }
        } catch (final IOException ioe) {
            log.error("Failed to read LDAP configuration from ldap.properties", ioe);
        }

        contextFactoryClassName = localProperties.getProperty(Constants.LDAP_CONTEXT_FACTORY_CLASS_NAME, DEFAULT_CONTEXT_FACTORY_CLASS_NAME);

        url = localProperties.getProperty(Constants.LDAP_URL, null);

        baseDN = localProperties.getProperty(Constants.LDAP_BASE_DN, null);

        userDNTemplate = localProperties.getProperty(Constants.LDAP_USER_DN_TEMPLATE, null);

        groupFilterTemplate = localProperties.getProperty(Constants.LDAP_GROUP_FILTER, null);

        try {
            int tries = Integer.parseInt(localProperties.getProperty(Constants.LDAP_RETRIES, String.valueOf(DEFAULT_RETRIES)));
            if (tries < 1) {
                retries = 1;
            } else {
                retries = Math.min(tries, MAX_RETRIES);
            }
        } catch (final NumberFormatException nfe) {
            log.warn("Invalid value for " + Constants.LDAP_RETRIES + " ({}), falling-back to default value of " + DEFAULT_RETRIES, localProperties.getProperty(Constants.LDAP_RETRIES));
            retries = DEFAULT_RETRIES;
        }

        try {
            long interval = Long.parseLong(localProperties.getProperty(Constants.LDAP_RETRY_INTERVAL, String.valueOf(DEFAULT_RETRY_INTERVAL)));
            if (interval < 0) {
                retryInterval = 0;
            } else {
                retryInterval = Math.min(interval, MAX_RETRY_INTERVAL);
            }
        } catch (final NumberFormatException nfe) {
            log.warn("Invalid value for " + Constants.LDAP_RETRY_INTERVAL + " ({}), falling-back to default value of " + DEFAULT_RETRY_INTERVAL, localProperties.getProperty(Constants.LDAP_RETRY_INTERVAL));
            retryInterval = DEFAULT_RETRY_INTERVAL;
        }

        final String fallback = localProperties.getProperty(Constants.LDAP_FALLBACK_TO_LOCAL);
        fallbackToLocalAuthentication = "true".equalsIgnoreCase(fallback) || "yes".equalsIgnoreCase(fallback);

        final String mapString = localProperties.getProperty(Constants.LDAP_USERNAME_MAP, null);
        if (mapString == null || mapString.trim().isEmpty()) {
            usernameMap = null;
        } else {
            String[] maps = mapString.split("\\s*(?<!\\\\),\\s*"); // Split on comma using \ as an escape character

            Map<String, String> map = new HashMap<>(maps.length);

            for (final String mapped : maps) {
                String[] split = mapped.split("\\s*(?<!\\\\)=\\s*"); // Split on equals using \ as an escape character

                if (split.length == 2) {
                    map.put(split[0], split[1]);
                } else {
                    log.warn("Ignoring confusing mapping: {}", mapped);
                }
            }

            usernameMap = Collections.unmodifiableMap(map);
        }

        final String template = localProperties.getProperty(Constants.LDAP_USERNAME_TEMPLATE, null);
        if (template == null || template.trim().isEmpty() || "{username}".equals(template)) {
            usernameTemplate = null;
        } else {
            usernameTemplate = template;
        }
    }

    @Override
    public void update(final Properties properties) {
        init(properties);
    }

    @Override
    public void start() {
    }

    @Override
    public void stop() {
    }

    /**
     * Authenticates the user against the LDAP server.
     *
     * If {@link fallbackToLocalAuthentication} is {@code true},
     * then authentication failures will return in this method returning
     * {@code null} which will cause Mirth to perform local-database
     * authentication.
     *
     * @return SUCCESS if the user was correctly authenticated, or either
     *         FAIL if the authentication or {@code null} if the
     *         authentication failed, depending upon the value of
     *         {@link fallbackToLocalAuthentication}.
     */
    @Override
    public LoginStatus authorizeUser(final String username, final String plainPassword) {

        String mappedUsername = mapUsername(username);
        if (!username.equals(mappedUsername)) {
            if (log.isDebugEnabled()) {
                log.debug("Mapped incoming username from {} to {}", username, mappedUsername);
            }
        }

        int tries = retries;
        while (tries > 0) {
            try {
                // We can either connect with an anonymous and/or admin DN and go
                // from there, or we can connect as the user trying to authenticate.
                //
                // Let's try the direct approach for now.

                performUserAuthenticationAndAuthorization(mappedUsername, plainPassword);

                if (log.isDebugEnabled()) {
                    log.debug("Successfully authenticated {} using server {}", mappedUsername, url);
                }

                // Check to see if we need to create a new local user
                UserController uc = ControllerFactory.getFactory().createUserController();

                User user = uc.getUser(null, username);

                if (user == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Must create new local user for {}", username);
                    }
                    user = new User();
                    user.setUsername(username);
                    uc.updateUser(user);
                }

                return new LoginStatus(Status.SUCCESS, null);
            } catch (final NamingException ne) {
                if (fallbackToLocalAuthentication) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to authenticate {} using server {}; falling-back to local authentication", username, url, ne);
                    }
                    return null;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to authenticate {} using server {}", username, url, ne);
                    }
                    return new LoginStatus(Status.FAIL, "Authentication failure");
                }
            } catch (final Exception e) {
                log.error("Error during LDAP authentication attempt; re-trying", e);
            }
            tries--;
            try {
                Thread.sleep(retryInterval);
            } catch (final InterruptedException ignored) {
            }
        }

        // Authentication did not succeed after X tries
        if (fallbackToLocalAuthentication) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate {} using server {}; falling-back to local authentication", username, url);
            }

            return null;
        } else {
            return new LoginStatus(Status.FAIL, null);
        }
    }

    /**
     * Map a user's username from the original user-supplied username
     * to one that should be used when authenticating to LDAP.
     *
     * @param username The username to map.
     *
     * @return The mapped username, which may be unchanged.
     */
    private String mapUsername(final String username) {
        if (username == null) {
            return null;
        }

        String mappedUsername;

        Map<String, String> map = usernameMap;
        if (map != null) {
            mappedUsername = map.get(username);

            if (mappedUsername == null) {
                mappedUsername = username;
            }
        } else {
            mappedUsername = username;
        }

        String template = usernameTemplate;
        if (template != null) {
            mappedUsername = template.replace("{username}", mappedUsername);
        }

        return mappedUsername;
    }

    /**
     * Authenticates against an LDAP server using the user's credentials directly.
     *
     * The username should be "bare" and will be converted into a dn by using
     * the {@link #LDAP_USER_DN_TEMPLATE}.
     *
     * @param username The user's username
     * @param password The user's password
     *
     * @return The username to use in the Mirth database
     *
     * @throws NamingException If there is an error
     */
    private String performUserAuthenticationAndAuthorization(final String username, final String password)
            throws NamingException {
        if (password == null) {
            throw new IllegalArgumentException("Null password is prohibited");
        }
        if (password.isEmpty()) {
            throw new IllegalArgumentException("Empty password is prohibited");
        }
        if (url == null) {
            throw new IllegalStateException("No LDAP URL configured.");
        }
        if (groupFilterTemplate == null) {
            throw new IllegalStateException("No LDAP group filter configured.");
        }

        String dn = userDNTemplate == null
                ? escapeFilterValue(username)
                : userDNTemplate.replace("{username}", escapeFilterValue(username));

        Properties props = new Properties();
        props.setProperty(Context.INITIAL_CONTEXT_FACTORY, contextFactoryClassName);
        props.setProperty(Context.PROVIDER_URL, url);
        props.setProperty(Context.SECURITY_PRINCIPAL, dn);
        props.setProperty(Context.SECURITY_CREDENTIALS, password);

        // TODO: Allow custom TLS configuration
//        props.put("java.naming.ldap.factory.socket","com.eterra.security.authz.dao.CustomSSLSocketFactory" );

        if (log.isDebugEnabled()) {
            log.debug("Connecting to LDAP URL {} as {}", url, dn);
        }

        DirContext ctx = null;
        try {
            ctx = new InitialLdapContext(props, null);

            SearchControls sc = new SearchControls();
            sc.setReturningAttributes(new String[]{"dn", "cn"});
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            sc.setTimeLimit(10000);

            String filter = groupFilterTemplate.replace("{username}", escapeFilterValue(username));

            if (log.isDebugEnabled()) {
                log.debug("Searching for groups using using filter={}", filter);
            }

            NamingEnumeration<SearchResult> results = ctx.search(baseDN, filter, sc);

            // We only care if at least one result is present
            if (results.hasMore()) {
                while (results.hasMore()) {
                    SearchResult result = results.next();
                    if (log.isDebugEnabled()) {
                        log.debug("LDAP User {} is in group {}", dn, result.getNameInNamespace());
                    }
                }
                return username;
            } else {
                throw new AuthenticationException("User is not in any required group");
            }
        } finally {
            if (ctx != null) {
                ctx.close();
            }
        }
    }

    @Override
    public Map<String, Object> getObjectsForSwaggerExamples() {
        return null;
    }

    /**
     * Filter components need to escape special chars.
     * Note that each piece of the filter needs to be escaped,
     * not the whole filter expression, for example:
     *
     * "(&(cn="+ esc("Admins") +")(member="+ esc("CN=Doe\\, Jöhn,OU=ImPeople,DC=ds,DC=augur,DC=com") +"))"
     *
     * Credit: Chris Janicki [https://stackoverflow.com/a/46008789/276232]
     *
     * @see Oracle Directory Server Enterprise Edition 11g Reference doc
     * @see https://docs.oracle.com/cd/E29127_01/doc.111170/e28969/ds-ldif-search-filters.htm#gdxoy
     * @param s A String field within the search expression
     * @return The escaped string, safe for use in the search expression.
     */
    private static String escapeFilterValue(final String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (final byte c : s.getBytes(StandardCharsets.UTF_8)) {
            if (c == '\\') {
                sb.append("\\5c");
            } else if (c == '*') {
                sb.append("\\2a");
            } else if (c == '(') {
                sb.append("\\28");
            } else if (c == ')') {
                sb.append("\\29");
            } else if (c == 0) {
                sb.append("\\00");
            } else if ((c & 0xff) > 127) {
                sb.append('\\').append(to2CharHexString(c));
            } // UTF-8's non-7-bit characters, e.g. é, á, etc...
            else {
                sb.append((char) c);
            }
        }

        return sb.toString();
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * @return The least significant 16 bits as a two-character hex string,
     * padded by a leading '0' if necessary.
     */
    private static String to2CharHexString(final int i) {
        return new String(new char[]{
                HEX[(i >> 4) & 0x0f],
                HEX[i & 0x0f],
        });
    }
}
