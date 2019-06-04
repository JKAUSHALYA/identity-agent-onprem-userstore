/*
 * Copyright (c) 2017, WSO2 Inc. (http://wso2.com) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.agent.userstore.manager.ldap;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.agent.userstore.config.ClaimConfiguration;
import org.wso2.carbon.identity.agent.userstore.constant.CommonConstants;
import org.wso2.carbon.identity.agent.userstore.constant.LDAPConstants;
import org.wso2.carbon.identity.agent.userstore.exception.UserStoreException;
import org.wso2.carbon.identity.agent.userstore.manager.common.UserStoreManager;
import org.wso2.carbon.identity.agent.userstore.util.JNDIUtil;
import org.wso2.carbon.identity.agent.userstore.util.UserStoreUtils;

import java.io.UnsupportedEncodingException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.naming.AuthenticationException;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 *  User Store org.wso2.carbon.identity.agent.outbound.manager for LDAP user stores.
 */
public class LDAPUserStoreManager implements UserStoreManager {

    private Map<String, String> userStoreProperties = null;
    private static Log log = LogFactory.getLog(LDAPUserStoreManager.class);
    private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";
    private static final String PROPERTY_REFERRAL_IGNORE = "ignore";
    private static final String MEMBER_UID = "memberUid";
    private boolean emptyRolesAllowed = false;
    private LDAPConnectionContext connectionSource;

    public LDAPUserStoreManager() {
    }

    public LDAPUserStoreManager(Map<String, String> userStoreProperties)
            throws UserStoreException {
        this.userStoreProperties = userStoreProperties;
        if (userStoreProperties == null) {
            throw new UserStoreException(
                    "User Store Properties Could not be found!");
        }
        // check if required configurations are in the user-mgt.xml
        checkRequiredUserStoreConfigurations();
        this.connectionSource = new LDAPConnectionContext(this.userStoreProperties);
    }

    /**
     * checks whether all the mandatory properties of user store are set.
     * @throws UserStoreException If any of the mandatory properties are not set in the userstore-mgt.xml.
     */
    private void checkRequiredUserStoreConfigurations() throws UserStoreException {

        log.debug("Checking LDAP configurations ");

        String domainName = userStoreProperties.get(LDAPConstants.DOMAIN_NAME);
        if (domainName == null || domainName.trim().length() == 0) {
            throw new UserStoreException(
                    "Required DomainName property is not set at the LDAP configurations");
        }

        String connectionURL = userStoreProperties.get(LDAPConstants.CONNECTION_URL);

        if (connectionURL == null || connectionURL.trim().length() == 0) {
            throw new UserStoreException(
                    "Required ConnectionURL property is not set at the LDAP configurations");
        }
        String connectionName = userStoreProperties.get(LDAPConstants.CONNECTION_NAME);
        if (connectionName == null || connectionName.trim().length() == 0) {
            throw new UserStoreException(
                    "Required ConnectionNme property is not set at the LDAP configurations");
        }
        String connectionPassword =
                userStoreProperties.get(LDAPConstants.CONNECTION_PASSWORD);
        if (connectionPassword == null || connectionPassword.trim().length() == 0) {
            throw new UserStoreException(
                    "Required ConnectionPassword property is not set at the LDAP configurations");
        }
        String userSearchBase = userStoreProperties.get(LDAPConstants.USER_SEARCH_BASE);
        if (userSearchBase == null || userSearchBase.trim().length() == 0) {
            throw new UserStoreException(
                    "Required UserSearchBase property is not set at the LDAP configurations");
        }
        String usernameListFilter =
                userStoreProperties.get(LDAPConstants.USER_NAME_LIST_FILTER);
        if (usernameListFilter == null || usernameListFilter.trim().length() == 0) {
            throw new UserStoreException(
                    "Required UserNameListFilter property is not set at the LDAP configurations");
        }

        String usernameSearchFilter =
                userStoreProperties.get(LDAPConstants.USER_NAME_SEARCH_FILTER);
        if (usernameSearchFilter == null || usernameSearchFilter.trim().length() == 0) {
            throw new UserStoreException(
                    "Required UserNameSearchFilter property is not set at the LDAP configurations");
        }

        String usernameAttribute =
                userStoreProperties.get(LDAPConstants.USER_NAME_ATTRIBUTE);
        if (usernameAttribute == null || usernameAttribute.trim().length() == 0) {
            throw new UserStoreException(
                    "Required UserNameAttribute property is not set at the LDAP configurations");
        }
        String groupSearchBase = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);
        if (groupSearchBase == null || groupSearchBase.trim().length() == 0) {
            throw new UserStoreException(
                    "Required GroupSearchBase property is not set at the LDAP configurations");
        }
        String groupNameListFilter =
                userStoreProperties.get(LDAPConstants.GROUP_NAME_LIST_FILTER);
        if (groupNameListFilter == null || groupNameListFilter.trim().length() == 0) {
            throw new UserStoreException(
                    "Required GroupNameListFilter property is not set at the LDAP configurations");
        }

        String groupNameSearchFilter =
                userStoreProperties.get(LDAPConstants.ROLE_NAME_FILTER);
        if (groupNameSearchFilter == null || groupNameSearchFilter.trim().length() == 0) {
            throw new UserStoreException(
                    "Required GroupNameSearchFilter property is not set at the LDAP configurations");
        }

        String groupNameAttribute =
                userStoreProperties.get(LDAPConstants.GROUP_NAME_ATTRIBUTE);
        if (groupNameAttribute == null || groupNameAttribute.trim().length() == 0) {
            throw new UserStoreException(
                    "Required GroupNameAttribute property is not set at the LDAP configurations");
        }
        String memebershipAttribute =
                userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
        if (memebershipAttribute == null || memebershipAttribute.trim().length() == 0) {
            throw new UserStoreException(
                    "Required MembershipAttribute property is not set at the LDAP configurations");
        }
        emptyRolesAllowed = Boolean.parseBoolean(userStoreProperties.get(LDAPConstants.EMPTY_ROLES_ALLOWED));
    }

    /**
     * {@inheritDoc}
     */
    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {

        boolean debug = log.isDebugEnabled();

        if (userName == null || credential == null) {
            return false;
        }

        userName = userName.trim();

        String password = (String) credential;
        password = password.trim();

        if (userName.equals("") || password.equals("")) {
            return false;
        }

        if (debug) {
            log.debug("Authenticating user " + userName);
        }

        boolean bValue = false;
        String name;
        // read DN patterns from user-mgt.xml
        String patterns = userStoreProperties.get(LDAPConstants.USER_DN_PATTERN);

        if (patterns != null && !patterns.isEmpty()) {

            if (debug) {
                log.debug("Using UserDNPatterns " + patterns);
            }

            // if the property is present, split it using # to see if there are
            // multiple patterns specified.
            String[] userDNPatternList = patterns.split(CommonConstants.XML_PATTERN_SEPERATOR);
            if (userDNPatternList.length > 0) {
                for (String userDNPattern : userDNPatternList) {
                    name = MessageFormat.format(userDNPattern, escapeSpecialCharactersForDN(userName));

                    if (debug) {
                        log.debug("Authenticating with " + name);
                    }
                    try {
                        bValue = this.bindAsUser(name, (String) credential);
                        if (bValue) {
                            break;
                        }
                    } catch (NamingException e) {
                        // do nothing if bind fails since we check for other DN
                        // patterns as well.
                        if (log.isDebugEnabled()) {
                            log.debug("Checking authentication with UserDN " + userDNPattern +
                                    "failed " + e.getMessage(), e);
                        }
                    }
                }
            }
        } else {
            name = getNameInSpaceForUserName(userName);
            try {
                if (name != null) {
                    if (debug) {
                        log.debug("Authenticating with " + name);
                    }
                    bValue = this.bindAsUser(name, (String) credential);
                }
            } catch (NamingException e) {
                String errorMessage = "Cannot bind user : " + userName;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }
        }

        return bValue;
    }

    /**
     * {@inheritDoc}
     */
    public boolean doCheckExistingUser(String userName) throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Searching for user " + userName);
        }
        boolean bFound = false;
        String userSearchFilter = userStoreProperties.get(LDAPConstants.USER_NAME_SEARCH_FILTER);
        userSearchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));
        try {
            String searchBase = null;
            String userDN = null;

            String userDNPattern = userStoreProperties.get(LDAPConstants.USER_DN_PATTERN);
            if (userDNPattern != null && userDNPattern.trim().length() > 0) {
                String[] patterns = userDNPattern.split(CommonConstants.XML_PATTERN_SEPERATOR);
                for (String pattern : patterns) {
                    searchBase = MessageFormat.format(pattern, escapeSpecialCharactersForDN(userName));
                    userDN = getNameInSpaceForUserName(userName, searchBase, userSearchFilter);
                    if (userDN != null && userDN.length() > 0) {
                        bFound = true;
                        break;
                    }
                }
            }

            if (!bFound) {
                searchBase = userStoreProperties.get(LDAPConstants.USER_SEARCH_BASE);
                userDN = getNameInSpaceForUserName(userName, searchBase, userSearchFilter);
                if (userDN != null && userDN.length() > 0) {
                    bFound = true;
                }
            }
        } catch (Exception e) {
            String errorMessage = "Error occurred while checking existence of user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
        if (log.isDebugEnabled()) {
            log.debug("User: " + userName + " exist: " + bFound);
        }
        return bFound;
    }

    /**
     * {@inheritDoc}
     */
    public Map<String, String> getUserClaimValues(String userName, String[] claimUris)
            throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Claim uris to retrieve for user " + userName + ": " + Arrays.toString(claimUris));
        }
        String[] propertyNames = convertClaimToPropertyNames(claimUris);
        if (log.isDebugEnabled()) {
            log.debug("propertyNames to retrieve for user " + userName + ": " + Arrays.toString(propertyNames));
        }

        String userAttributeSeparator = ",";
        String userDN = null;

        // read list of patterns from user-mgt.xml
        String patterns = userStoreProperties.get(LDAPConstants.USER_DN_PATTERN);

        if (patterns != null && !patterns.isEmpty()) {

            if (log.isDebugEnabled()) {
                log.debug("Using User DN Patterns " + patterns);
            }

            if (patterns.contains(CommonConstants.XML_PATTERN_SEPERATOR)) {
                userDN = getNameInSpaceForUserName(userName);
            } else {
                userDN = MessageFormat.format(patterns, escapeSpecialCharactersForDN(userName));
            }
        }

        Map<String, String> values = new HashMap<>();
        DirContext dirContext = this.connectionSource.getContext();
        String userSearchFilter = userStoreProperties.get(LDAPConstants.USER_NAME_SEARCH_FILTER);
        String searchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));

        NamingEnumeration<?> answer = null;
        NamingEnumeration<?> attrs = null;
        NamingEnumeration<?> allAttrs = null;
        try {
            if (userDN != null) {
                SearchControls searchCtls = new SearchControls();
                searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                if (propertyNames[0].equals(CommonConstants.WILD_CARD_FILTER)) {
                    propertyNames = null;
                }
                searchCtls.setReturningAttributes(propertyNames);

                try {
                    answer = dirContext.search(escapeDNForSearch(userDN), searchFilter, searchCtls);
                } catch (PartialResultException e) {
                    // can be due to referrals in AD. so just ignore error
                    String errorMessage = "Error occurred while searching directory context for user : "
                            + userDN + " searchFilter : " + searchFilter;
                    if (isIgnorePartialResultException()) {
                        if (log.isDebugEnabled()) {
                            log.debug(errorMessage, e);
                        }
                    } else {
                        throw new UserStoreException(errorMessage, e);
                    }
                } catch (NamingException e) {
                    String errorMessage = "Error occurred while searching directory context for user : "
                            + userDN + " searchFilter : " + searchFilter;
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage, e);
                    }
                    throw new UserStoreException(errorMessage, e);
                }
            } else {
                answer = this.searchForUser(searchFilter, propertyNames, dirContext);
            }
            assert answer != null;
            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attributes = sr.getAttributes();
                if (attributes != null) {
                    for (allAttrs = attributes.getAll(); allAttrs.hasMore(); ) {
                        Attribute attribute = (Attribute) allAttrs.next();
                        if (attribute != null) {
                            StringBuilder attrBuffer = new StringBuilder();
                            for (attrs = attribute.getAll(); attrs.hasMore(); ) {
                                Object attObject = attrs.next();
                                String attr = null;
                                if (attObject instanceof String) {
                                    attr = (String) attObject;
                                } else if (attObject instanceof byte[]) {
                                    //if the attribute type is binary base64 encoded string will be returned
                                    attr = new String(Base64.encodeBase64((byte[]) attObject), "UTF-8");
                                }

                                if (attr != null && attr.trim().length() > 0) {
                                    String attrSeparator = userStoreProperties.get(MULTI_ATTRIBUTE_SEPARATOR);
                                    if (attrSeparator != null && !attrSeparator.trim().isEmpty()) {
                                        userAttributeSeparator = attrSeparator;
                                    }
                                    attrBuffer.append(attr).append(userAttributeSeparator);
                                }
                                String value = attrBuffer.toString();

                            /*
                             * Length needs to be more than userAttributeSeparator.length() for a valid
                             * attribute, since we
                             * attach userAttributeSeparator
                             */
                                if (value.trim().length() > userAttributeSeparator.length()) {
                                    value = value.substring(0, value.length() - userAttributeSeparator.length());
                                    values.put(attribute.getID(), value);
                                }

                            }

                        }
                    }
                }
            }

        } catch (NamingException e) {
            String errorMessage = "Error occurred while getting user property values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (UnsupportedEncodingException e) {
            String errorMessage = "Error occurred while Base64 encoding property values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            // close the naming enumeration and free up resource
            JNDIUtil.closeNamingEnumeration(attrs);
            JNDIUtil.closeNamingEnumeration(answer);
            // close directory context
            JNDIUtil.closeContext(dirContext);
        }

        Map<String, String> claimValues = new HashMap<>();
        Map<String, String> claimMap = ClaimConfiguration.getConfiguration().getClaimMap();
        for (String claim : claimUris) {
            Optional<String> value = Optional.ofNullable(values.get(claimMap.get(claim)));
            value.ifPresent(s -> claimValues.put(claim, s));
        }

        return claimValues;
    }

    private String[] convertClaimToPropertyNames(String[] claimUris) {

        if (claimUris != null) {
            List<String> propertyNames = new ArrayList<>();
            Map<String, String> claimMap = ClaimConfiguration.getConfiguration().getClaimMap();
            for (String claimUrl : claimUris) {
                String propertyName = claimMap.get(claimUrl);
                if (propertyName != null) {
                    propertyNames.add(propertyName);
                }
            }
            return propertyNames.toArray(new String[propertyNames.size()]);
        } else {
            return new String[0];
        }

    }

    /**
     * {@inheritDoc}
     */
    public String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {
        boolean debug = log.isDebugEnabled();
        String[] userNames = new String[0];

        if (maxItemLimit == 0) {
            return userNames;
        }

        int givenMax;
        int searchTime;

        try {
            givenMax =
                    Integer.parseInt(userStoreProperties.get(CommonConstants.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = CommonConstants.MAX_USER_LIST;
        }

        try {
            searchTime =
                    Integer.parseInt(userStoreProperties.get(CommonConstants.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = CommonConstants.MAX_SEARCH_TIME;
        }

        if (maxItemLimit <= 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setCountLimit(maxItemLimit);
        searchCtls.setTimeLimit(searchTime);

        if (filter.contains("?") || filter.contains("**")) {
            throw new UserStoreException(
                    "Invalid character sequence entered for user search. Please enter valid sequence.");
        }

        StringBuilder searchFilter =
                new StringBuilder(
                        userStoreProperties.get(LDAPConstants.USER_NAME_LIST_FILTER));
        String searchBases = userStoreProperties.get(LDAPConstants.USER_SEARCH_BASE);

        String userNameProperty =
                userStoreProperties.get(LDAPConstants.USER_NAME_ATTRIBUTE);

        String serviceNameAttribute = "sn";

        StringBuilder finalFilter = new StringBuilder();

        // read the display name attribute - if provided
        String displayNameAttribute =
                userStoreProperties.get(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);

        String[] returnedAtts;

        if (StringUtils.isNotEmpty(displayNameAttribute)) {
            returnedAtts =
                    new String[] { userNameProperty, serviceNameAttribute,
                            displayNameAttribute };
            finalFilter.append("(&").append(searchFilter).append("(").append(displayNameAttribute)
                    .append("=").append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        } else {
            returnedAtts = new String[] { userNameProperty, serviceNameAttribute };
            finalFilter.append("(&").append(searchFilter).append("(").append(userNameProperty).append("=")
                    .append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");
        }

        if (debug) {
            log.debug("Listing users. SearchBase: " + searchBases + " Constructed-Filter: " + finalFilter.toString());
            log.debug("Search controls. Max Limit: " + maxItemLimit + " Max Time: " + searchTime);
        }

        searchCtls.setReturningAttributes(returnedAtts);
        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;
        List<String> list = new ArrayList<>();

        try {
            dirContext = connectionSource.getContext();
            // handle multiple search bases
            String[] searchBaseArray = searchBases.split(CommonConstants.XML_PATTERN_SEPERATOR);

            for (String searchBase : searchBaseArray) {

                answer = dirContext.search(escapeDNForSearch(searchBase), finalFilter.toString(), searchCtls);
                while (answer.hasMoreElements()) {
                    SearchResult sr = answer.next();
                    if (sr.getAttributes() != null) {
                        log.debug("Result found ..");
                        Attribute attr = sr.getAttributes().get(userNameProperty);

                        // If this is a service principle, just ignore and
                        // iterate rest of the array. The entity is a service if
                        // value of surname is Service

                        Attribute attrSurname = sr.getAttributes().get(serviceNameAttribute);

                        if (attrSurname != null) {
                            if (debug) {
                                log.debug(serviceNameAttribute + " : " + attrSurname);
                            }
                            String serviceName = (String) attrSurname.get();
                            if (serviceName != null
                                    && serviceName
                                    .equals(LDAPConstants.SERVER_PRINCIPAL_ATTRIBUTE_VALUE)) {
                                continue;
                            }
                        }

                        if (attr != null) {
                            String name = (String) attr.get();
                            list.add(name);
                        }
                    }
                }
            }
            userNames = list.toArray(new String[list.size()]);
            Arrays.sort(userNames);

            if (debug) {
                for (String username : userNames) {
                    log.debug("result: " + username);
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter + "max limit : " + maxItemLimit;
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
            } else {
                throw new UserStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage =
                    "Error occurred while getting user list for filter : " + filter + "max limit : " + maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }
        return userNames;
    }

    /**
     * {@inheritDoc}
     */
    public String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException {

        if (maxItemLimit == 0) {
            return new String[0];
        }

        int givenMax;

        int searchTime;

        try {
            givenMax = Integer.parseInt(userStoreProperties.
                    get(CommonConstants.PROPERTY_MAX_ROLE_LIST));
        } catch (Exception e) {
            givenMax = CommonConstants.MAX_USER_LIST;
        }

        try {
            searchTime = Integer.parseInt(userStoreProperties.
                    get(CommonConstants.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = CommonConstants.MAX_SEARCH_TIME;
        }

        if (maxItemLimit < 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }

        List<String> externalRoles = new ArrayList<>();

        // handling multiple search bases
        String searchBases = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);
        String[] searchBaseArray = searchBases.split(CommonConstants.XML_PATTERN_SEPERATOR);
        for (String searchBase : searchBaseArray) {
            // get the role list from the group search base
            externalRoles.addAll(getLDAPRoleNames(searchTime, filter, maxItemLimit,
                    userStoreProperties.get(LDAPConstants.GROUP_NAME_LIST_FILTER),
                    userStoreProperties.get(LDAPConstants.GROUP_NAME_ATTRIBUTE),
                    searchBase));
        }

        return externalRoles.toArray(new String[externalRoles.size()]);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String[] doGetExternalRoleListOfUser(String userName) throws UserStoreException {

        // Get the effective search base
        String searchBase = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);
        return getLDAPRoleListOfUser(userName, searchBase);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException {

        boolean debug = log.isDebugEnabled();
        String searchBases = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        // read the roles with this membership property
        String searchFilter = userStoreProperties.get(LDAPConstants.GROUP_NAME_LIST_FILTER);
        String membershipProperty = userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE);

        if (membershipProperty == null || membershipProperty.length() < 1) {
            throw new UserStoreException("Please set membership attribute");
        }

        String roleNameProperty = userStoreProperties.get(LDAPConstants.GROUP_NAME_ATTRIBUTE);
        String userDNPattern = userStoreProperties.get(LDAPConstants.USER_DN_PATTERN);
        String nameInSpace;
        if (org.apache.commons.lang.StringUtils.isNotEmpty(userDNPattern) &&
                !userDNPattern.contains(CommonConstants.XML_PATTERN_SEPERATOR)) {
            nameInSpace = MessageFormat.format(userDNPattern, escapeSpecialCharactersForDN(userName));
        } else {
            nameInSpace = this.getNameInSpaceForUserName(userName);
        }

        String membershipValue;
        if (nameInSpace != null) {
            try {
                LdapName ldn = new LdapName(nameInSpace);
                membershipValue = escapeLdapNameForFilter(ldn);
            } catch (InvalidNameException e) {
                log.error("Error while creating LDAP name from: " + nameInSpace);
                throw new UserStoreException(
                        "Invalid naming org.wso2.carbon.identity.agent.outbound.exception for : " + nameInSpace, e);
            }
        } else {
            return false;
        }

        searchFilter = "(&" + searchFilter + "(" + membershipProperty + "=" + membershipValue + "))";
        String returnedAtts[] = { roleNameProperty };
        searchCtls.setReturningAttributes(returnedAtts);

        if (debug) {
            log.debug("Do check whether the user : " + userName + " is in role: " + roleName);
            log.debug("Search filter : " + searchFilter);
            for (String retAttrib : returnedAtts) {
                log.debug("Requesting attribute: " + retAttrib);
            }
        }

        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;
        try {
            dirContext = connectionSource.getContext();

            if (debug) {
                log.debug("Do check whether the user: " + userName + " is in role: " + roleName);
                log.debug("Search filter: " + searchFilter);
                for (String retAttrib : returnedAtts) {
                    log.debug("Requesting attribute: " + retAttrib);
                }
            }

            searchFilter = "(&" + searchFilter + "(" + membershipProperty + "=" + membershipValue +
                    ") (" + roleNameProperty + "=" + escapeSpecialCharactersForFilter(roleName) + "))";

            // handle multiple search bases
            String[] searchBaseArray = searchBases.split(CommonConstants.XML_PATTERN_SEPERATOR);

            for (String searchBase : searchBaseArray) {
                answer = dirContext.search(escapeDNForSearch(searchBase), searchFilter, searchCtls);

                if (answer.hasMoreElements()) {
                    if (debug) {
                        log.debug("User: " + userName + " in role: " + roleName);
                    }
                    return true;
                }

                if (debug) {
                    log.debug("User: " + userName + " NOT in role: " + roleName);
                }
            }
        } catch (NamingException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage(), e);
            }
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String[] doGetUserListOfRole(String roleName, int maxItemLimit) throws UserStoreException {

        boolean debug = log.isDebugEnabled();
        List<String> userList = new ArrayList<String>();
        String[] names = new String[0];
        int givenMax = CommonConstants.MAX_USER_ROLE_LIST;
        int searchTime = CommonConstants.MAX_SEARCH_TIME;

        try {
            givenMax =
                    Integer.parseInt(userStoreProperties.get(CommonConstants.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = CommonConstants.MAX_USER_ROLE_LIST;
        }

        try {
            searchTime =
                    Integer.parseInt(userStoreProperties.get(CommonConstants.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = CommonConstants.MAX_SEARCH_TIME;
        }

        if (maxItemLimit <= 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }

        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;
        try {
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchCtls.setTimeLimit(searchTime);
            searchCtls.setCountLimit(maxItemLimit);

            String searchFilter = userStoreProperties.get(LDAPConstants.GROUP_NAME_LIST_FILTER);
            String roleNameProperty = userStoreProperties.get(LDAPConstants.GROUP_NAME_ATTRIBUTE);
            searchFilter = "(&" + searchFilter + "(" + roleNameProperty + "=" + escapeSpecialCharactersForFilter(
                    roleName) + "))";

            String membershipProperty = userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
            String returnedAtts[] = { membershipProperty };
            searchCtls.setReturningAttributes(returnedAtts);
            List<String> userDNList = new ArrayList<String>();

            SearchResult sr = null;
            dirContext = connectionSource.getContext();

            // handling multiple search bases
            String searchBases = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);
            String[] roleSearchBaseArray = searchBases.split("#");
            for (String searchBase : roleSearchBaseArray) {
                if (debug) {
                    log.debug("Searching role: " + roleName + " SearchBase: "
                            + searchBase + " SearchFilter: " + searchFilter);
                }
                try {
                    // read the DN of users who are members of the group
                    answer = dirContext.search(escapeDNForSearch(searchBase), searchFilter, searchCtls);
                    int count = 0;
                    if (answer.hasMore()) { // to check if there is a result
                        while (answer.hasMore()) { // to check if there are more than one group
                            if (count > 0) {
                                throw new UserStoreException("More than one group exist with name");
                            }
                            sr = answer.next();
                            count++;
                        }
                        break;
                    }
                } catch (NamingException e) {
                    // ignore
                    if (log.isDebugEnabled()) {
                        log.debug(e);
                    }
                }
            }

            if (debug) {
                log.debug("Found role: " + sr.getNameInNamespace());
            }

            // read the member attribute and get DNs of the users
            Attributes attributes = sr.getAttributes();
            if (attributes != null) {
                NamingEnumeration attributeEntry = null;
                for (attributeEntry = attributes.getAll(); attributeEntry.hasMore(); ) {
                    Attribute valAttribute = (Attribute) attributeEntry.next();
                    if (membershipProperty.equals(valAttribute.getID())) {
                        NamingEnumeration values = null;
                        for (values = valAttribute.getAll(); values.hasMore(); ) {
                            String value = values.next().toString();
                            if (userDNList.size() >= maxItemLimit) {
                                break;
                            }
                            userDNList.add(value);
                            if (debug) {
                                log.debug("Found attribute: " + membershipProperty + " value: " + value);
                            }
                        }
                    }
                }
            }

            if (MEMBER_UID.equals(userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE))) {
                /* when the GroupEntryObjectClass is posixGroup, membership attribute is memberUid. We have to
                   retrieve the DN using the memberUid.
                   This procedure has to make an extra call to ldap. alternatively this can be done with a single ldap
                   search using the memberUid and retrieving the display name and username. */
                List<String> userDNListNew = new ArrayList<>();

                for (String user : userDNList) {
                    String userDN = getNameInSpaceForUserName(user);
                    userDNListNew.add(userDN);
                }
                userDNList = userDNListNew;
            }

            // iterate over users' DN list and get userName and display name
            // attribute values
            String userNameProperty = userStoreProperties.get(LDAPConstants.USER_NAME_ATTRIBUTE);
            String displayNameAttribute = userStoreProperties.get(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);
            String[] returnedAttributes = { userNameProperty, displayNameAttribute };

            for (String user : userDNList) {
                if (debug) {
                    log.debug("Getting name attributes of: " + user);
                }
                Attributes userAttributes;
                try {
                    // '\' and '"' characters need another level of escaping before searching
                    userAttributes = dirContext.getAttributes(escapeDNForSearch(user), returnedAttributes);

                    String displayName = null;
                    String userName = null;
                    if (userAttributes != null) {
                        Attribute userNameAttribute = userAttributes.get(userNameProperty);
                        if (userNameAttribute != null) {
                            userName = (String) userNameAttribute.get();
                            if (debug) {
                                log.debug("UserName: " + userName);
                            }
                        }
                        if (org.apache.commons.lang.StringUtils.isNotEmpty(displayNameAttribute)) {
                            Attribute displayAttribute = userAttributes.get(displayNameAttribute);
                            if (displayAttribute != null) {
                                displayName = (String) displayAttribute.get();
                            }
                            if (debug) {
                                log.debug("DisplayName: " + displayName);
                            }
                        }
                    }

                    // Username will be null in the special case where the
                    // username attribute has changed to another
                    // and having different userNameProperty than the current
                    // user-mgt.xml
                    if (userName != null) {
                        user = UserStoreUtils.getCombinedName(userName, displayName);
                        userList.add(user);
                        if (debug) {
                            log.debug(user + " is added to the result list");
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("User " + user + " doesn't have the user name property : " +
                                    userNameProperty);
                        }
                    }

                } catch (NamingException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error in reading user information in the user store for the user " +
                                user + e.getMessage(), e);
                    }
                }

            }
            names = userList.toArray(new String[userList.size()]);

        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage = "Error in reading user information in the user store";
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
            } else {
                throw new UserStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage = "Error in reading user information in the user store";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }
        return names;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean doCheckExistingRole(String roleName) throws UserStoreException {

        boolean debug = log.isDebugEnabled();
        boolean isExisting = false;

        if (debug) {
            log.debug("Searching for role: " + roleName);
        }
        String searchFilter = userStoreProperties.get(LDAPConstants.GROUP_NAME_LIST_FILTER);
        String roleNameProperty = userStoreProperties.get(LDAPConstants.GROUP_NAME_ATTRIBUTE);
        searchFilter = "(&" + searchFilter + "(" + roleNameProperty + "=" +
                escapeSpecialCharactersForFilter(roleName) + "))";
        String searchBases = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);

        if (debug) {
            log.debug("Using search filter: " + searchFilter);
        }
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setReturningAttributes(new String[] { roleNameProperty });
        NamingEnumeration<SearchResult> answer = null;
        DirContext dirContext = null;

        try {
            dirContext = connectionSource.getContext();
            String[] roleSearchBaseArray = searchBases.split(CommonConstants.XML_PATTERN_SEPERATOR);
            for (String searchBase : roleSearchBaseArray) {
                if (debug) {
                    log.debug("Searching in " + searchBase);
                }
                try {
                    answer = dirContext.search(escapeDNForSearch(searchBase), searchFilter, searchCtls);
                    if (answer.hasMoreElements()) {
                        isExisting = true;
                        break;
                    }
                } catch (NamingException e) {
                    if (log.isDebugEnabled()) {
                        log.debug(e);
                    }
                }
            }
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }
        if (debug) {
            log.debug("Is role: " + roleName + " exist: " + isExisting);
        }
        return isExisting;
    }

    @Override
    public void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles)
            throws UserStoreException {

        // get the DN of the user entry
        String userNameDN = this.getNameInSpaceForUserName(userName);
        String membershipAttribute =
                userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
    /*
     * check deleted roles and delete member entries from relevant groups.
     */
        String errorMessage = null;
        String roleSearchFilter = null;

        DirContext mainDirContext = this.connectionSource.getContext();

        try {
            if (deletedRoles != null && deletedRoles.length != 0) {
                // perform validation for empty role occurrences before
                // updating in LDAP
                // check whether this is shared roles and where shared roles are
                // enable

                for (String deletedRole : deletedRoles) {
                    String searchFilter = userStoreProperties.get(LDAPConstants.ROLE_NAME_FILTER);
                    roleSearchFilter = searchFilter.replace("?", escapeSpecialCharactersForFilter(deletedRole));
                    String[] returningAttributes = new String[] { membershipAttribute };
                    String searchBase = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);
                    NamingEnumeration<SearchResult> groupResults =
                            searchInGroupBase(roleSearchFilter,
                                    returningAttributes,
                                    SearchControls.SUBTREE_SCOPE,
                                    mainDirContext,
                                    searchBase);
                    SearchResult resultedGroup = null;
                    if (groupResults.hasMore()) {
                        resultedGroup = groupResults.next();
                    }
                    if (resultedGroup != null && isOnlyUserInRole(userNameDN, resultedGroup) &&
                            !emptyRolesAllowed) {
                        errorMessage =
                                userName + " is the only user in the role: " + deletedRole +
                                        ". Hence can not delete user from role.";
                        throw new UserStoreException(errorMessage);
                    }

                    JNDIUtil.closeNamingEnumeration(groupResults);
                }
                // if empty role violation does not happen, continue
                // updating the LDAP.
                for (String deletedRole : deletedRoles) {

                    String searchFilter = userStoreProperties.get(LDAPConstants.ROLE_NAME_FILTER);

                    if (doCheckExistingRole(deletedRole)) {
                        roleSearchFilter = searchFilter.replace("?", escapeSpecialCharactersForFilter(deletedRole));
                        String[] returningAttributes = new String[] { membershipAttribute };
                        String searchBase = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);
                        NamingEnumeration<SearchResult> groupResults =
                                searchInGroupBase(roleSearchFilter,
                                        returningAttributes,
                                        SearchControls.SUBTREE_SCOPE,
                                        mainDirContext,
                                        searchBase);
                        SearchResult resultedGroup = null;
                        String groupDN = null;
                        if (groupResults.hasMore()) {
                            resultedGroup = groupResults.next();
                            groupDN = resultedGroup.getName();
                        }
                        modifyUserInRole(userNameDN, groupDN, DirContext.REMOVE_ATTRIBUTE, searchBase);
                        JNDIUtil.closeNamingEnumeration(groupResults);
                    } else {
                        errorMessage = "The role: " + deletedRole + " does not exist.";
                        throw new UserStoreException(errorMessage);
                    }
                }
            }
            if (newRoles != null && newRoles.length != 0) {

                for (String newRole : newRoles) {
                    String searchFilter = userStoreProperties.get(LDAPConstants.ROLE_NAME_FILTER);

                    if (doCheckExistingRole(newRole)) {
                        roleSearchFilter = searchFilter.replace("?", escapeSpecialCharactersForFilter(newRole));
                        String[] returningAttributes = new String[] { membershipAttribute };
                        String searchBase = userStoreProperties.get(LDAPConstants.GROUP_SEARCH_BASE);

                        NamingEnumeration<SearchResult> groupResults =
                                searchInGroupBase(roleSearchFilter,
                                        returningAttributes,
                                        SearchControls.SUBTREE_SCOPE,
                                        mainDirContext,
                                        searchBase);
                        SearchResult resultedGroup = null;
                        // assume only one group with given group name
                        String groupDN = null;
                        if (groupResults.hasMore()) {
                            resultedGroup = groupResults.next();
                            groupDN = resultedGroup.getName();
                        }
                        if (resultedGroup != null && !isUserInRole(userNameDN, resultedGroup)) {
                            modifyUserInRole(userNameDN, groupDN, DirContext.ADD_ATTRIBUTE,
                                    searchBase);
                        } else {
                            errorMessage =
                                    "User: " + userName + " already belongs to role: " +
                                            groupDN;
                            throw new UserStoreException(errorMessage);
                        }

                        JNDIUtil.closeNamingEnumeration(groupResults);

                    } else {
                        errorMessage = "The role: " + newRole + " does not exist.";
                        throw new UserStoreException(errorMessage);
                    }
                }
            }

        } catch (NamingException e) {
            errorMessage = "Error occurred while modifying the role list of user: " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeContext(mainDirContext);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getConnectionStatus() throws UserStoreException {
        connectionSource.getContext();
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setUserStoreProperties(Map<String, String> userStoreProperties) throws UserStoreException {
        this.userStoreProperties = userStoreProperties;
        if (userStoreProperties == null) {
            throw new UserStoreException(
                    "User Store Properties Could not be found!");
        }
        // check if required configurations are in the user-mgt.xml
        checkRequiredUserStoreConfigurations();
        this.connectionSource = new LDAPConnectionContext(this.userStoreProperties);
    }

    /**
     * Returns the list of role names for the given search base and other
     * parameters.
     * @param searchTime Maximum search time
     * @param filter Filter for searching role names
     * @param maxItemLimit Maximum number of roles required
     * @param searchFilter Group name search filter
     * @param roleNameProperty Attribute name of the group in LDAP user store.
     * @param searchBase Group search base.
     * @return The list of roles in the given search base.
     * @throws UserStoreException If an error occurs while retrieving the required information.
     */
    private List<String> getLDAPRoleNames(int searchTime, String filter, int maxItemLimit,
            String searchFilter, String roleNameProperty,
            String searchBase)
            throws UserStoreException {
        boolean debug = log.isDebugEnabled();
        List<String> roles = new ArrayList<>();

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setCountLimit(maxItemLimit);
        searchCtls.setTimeLimit(searchTime);

        String returnedAtts[] = { roleNameProperty };
        searchCtls.setReturningAttributes(returnedAtts);

        StringBuilder finalFilter = new StringBuilder();
        finalFilter.append("(&").append(searchFilter).append("(").append(roleNameProperty).append("=")
                .append(escapeSpecialCharactersForFilterWithStarAsRegex(filter)).append("))");

        if (debug) {
            log.debug("Listing roles. SearchBase: " + searchBase + " ConstructedFilter: " +
                    finalFilter.toString());
        }

        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;

        try {
            dirContext = connectionSource.getContext();
            answer = dirContext.search(escapeDNForSearch(searchBase), finalFilter.toString(), searchCtls);

            while (answer.hasMoreElements()) {
                SearchResult sr = answer.next();
                if (sr.getAttributes() != null) {
                    Attribute attr = sr.getAttributes().get(roleNameProperty);
                    if (attr != null) {
                        String name = (String) attr.get();
                        roles.add(name);
                    }
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage = "Error occurred while getting LDAP role names. SearchBase: "
                    + searchBase + " ConstructedFilter: " + finalFilter.toString();
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
            } else {
                throw new UserStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage = "Error occurred while getting LDAP role names. SearchBase: "
                    + searchBase + " ConstructedFilter: " + finalFilter.toString();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }

        if (debug) {
            for (String role : roles) {
                log.debug("result: " + role);
            }
        }

        return roles;
    }

    /**
     * @param dn Distinguised name of the user to be used for connecting to the LDAP userstore.
     * @param credentials Password of the user to be used for connecting to the LDAP userstore.
     * @return true if the username and the credentials are valid. false otherwise.
     * @throws javax.naming.NamingException If there is an issue authenticating the user
     * @throws UserStoreException If there is an issue in closing the connection
     */
    private boolean bindAsUser(String dn, String credentials) throws NamingException,
            UserStoreException {
        boolean isAuthed = false;
        boolean debug = log.isDebugEnabled();
        LdapContext cxt = null;
        try {
            // cxt = new InitialLdapContext(env, null);
            cxt = this.connectionSource.getContextWithCredentials(dn, credentials);
            isAuthed = true;
        } catch (AuthenticationException e) {
            // we avoid throwing an org.wso2.carbon.identity.agent.outbound.exception here since we throw that
            // org.wso2.carbon.identity.agent.outbound.exception
            // in a one level above this.
            if (debug) {
                log.debug("Authentication failed " + e);
            }

        } finally {
            JNDIUtil.closeContext(cxt);
        }

        if (debug) {
            log.debug("User: " + dn + " is authnticated: " + isAuthed);
        }
        return isAuthed;
    }

    /**
     * @param searchFilter Username search filter.
     * @param returnedAtts Required attribute list of the user
     * @param dirContext LDAP connection context.
     * @return Search results for the given user.
     * @throws UserStoreException If an error occurs while searching.
     */
    private NamingEnumeration<SearchResult> searchForUser(String searchFilter,
            String[] returnedAtts,
            DirContext dirContext)
            throws UserStoreException {
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String searchBases = userStoreProperties.get(LDAPConstants.USER_SEARCH_BASE);
        if (returnedAtts.length > 0 && CommonConstants.WILD_CARD_FILTER.equals(returnedAtts[0])) {
            returnedAtts = null;
        }
        searchCtls.setReturningAttributes(returnedAtts);

        if (log.isDebugEnabled()) {
            try {
                log.debug("Searching for user with SearchFilter: "
                        + searchFilter + " in SearchBase: " + dirContext.getNameInNamespace());
            } catch (NamingException e) {
                log.debug("Error while getting DN of search base", e);
            }
            if (returnedAtts == null) {
                log.debug("No attributes requested");
            } else {
                for (String attribute : returnedAtts) {
                    log.debug("Requesting attribute :" + attribute);
                }
            }
        }

        String[] searchBaseAraay = searchBases.split(CommonConstants.XML_PATTERN_SEPERATOR);
        NamingEnumeration<SearchResult> answer = null;

        try {
            for (String searchBase : searchBaseAraay) {
                answer = dirContext.search(escapeDNForSearch(searchBase), searchFilter, searchCtls);
                if (answer.hasMore()) {
                    return answer;
                }
            }
        } catch (PartialResultException e) {
            // can be due to referrals in AD. so just ignore error
            String errorMessage = "Error occurred while search user for filter : " + searchFilter;
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
            } else {
                throw new UserStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage = "Error occurred while search user for filter : " + searchFilter;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
        return answer;
    }

    /**
     * @param userName Username of the user.
     * @return DN of the user whose username is given.
     * @throws UserStoreException If an error occurs while searching for user.
     */
    private String getNameInSpaceForUserName(String userName) throws UserStoreException {
        String searchBase;
        String userSearchFilter = userStoreProperties.get(LDAPConstants.USER_NAME_SEARCH_FILTER);
        userSearchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));
        String userDNPattern = userStoreProperties.get(LDAPConstants.USER_DN_PATTERN);
        if (userDNPattern != null && userDNPattern.trim().length() > 0) {
            String[] patterns = userDNPattern.split(CommonConstants.XML_PATTERN_SEPERATOR);
            for (String pattern : patterns) {
                searchBase = MessageFormat.format(pattern, escapeSpecialCharactersForDN(userName));
                String userDN = getNameInSpaceForUserName(userName, searchBase, userSearchFilter);
                // check in another DN pattern
                if (userDN != null) {
                    return userDN;
                }
            }
        }

        searchBase = userStoreProperties.get(LDAPConstants.USER_SEARCH_BASE);

        return getNameInSpaceForUserName(userName, searchBase, userSearchFilter);

    }

    /**
     * @param userName Username of the user.
     * @param searchBase Searchbase which the user should be searched for.
     * @param searchFilter Search filter of the username.
     * @return DN of the user whose usename is given.
     * @throws UserStoreException If an error occurs while connecting to the LDAP userstore.
     */
    private String getNameInSpaceForUserName(String userName, String searchBase, String searchFilter)
            throws UserStoreException {
        boolean debug = log.isDebugEnabled();

        String userDN = null;

        DirContext dirContext = this.connectionSource.getContext();
        NamingEnumeration<SearchResult> answer = null;
        try {
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            if (log.isDebugEnabled()) {
                try {
                    log.debug("Searching for user with SearchFilter: "
                            + searchFilter + " in SearchBase: " + dirContext.getNameInNamespace());
                } catch (NamingException e) {
                    log.debug("Error while getting DN of search base", e);
                }
            }
            SearchResult userObj;
            String[] searchBases = searchBase.split(CommonConstants.XML_PATTERN_SEPERATOR);
            for (String base : searchBases) {
                answer = dirContext.search(escapeDNForSearch(base), searchFilter, searchCtls);
                if (answer.hasMore()) {
                    userObj = answer.next();
                    if (userObj != null) {
                        //no need to decode since , if decoded the whole string, can't be encoded again
                        //eg CN=Hello\,Ok=test\,test, OU=Industry
                        userDN = userObj.getNameInNamespace();
                        break;
                    }
                }
            }
            if (debug) {
                log.debug("Name in space for " + userName + " is " + userDN);
            }
        } catch (Exception e) {
            log.debug(e.getMessage(), e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }
        return userDN;
    }

    /**
     * @param dnPartial  Partial DN of the user
     * @return String with escape characters removed.
     */
    private String escapeSpecialCharactersForFilter(String dnPartial) {
        boolean replaceEscapeCharacters = true;
        dnPartial = dnPartial.replace("\\*", "*");

        String replaceEscapeCharactersAtUserLoginString = userStoreProperties
                .get(CommonConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < dnPartial.length(); i++) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(currentChar);
                }
            }
            return sb.toString();
        } else {
            return dnPartial;
        }
    }

    /**
     * @param text DN which the escape characters to be removed.
     * @return String with escape characters removed.
     */
    private String escapeSpecialCharactersForDN(String text) {
        boolean replaceEscapeCharacters = true;
        text = text.replace("\\*", "*");

        String replaceEscapeCharactersAtUserLoginString = userStoreProperties
                .get(CommonConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            if ((text.length() > 0) && ((text.charAt(0) == ' ') || (text.charAt(0) == '#'))) {
                sb.append('\\'); // add the leading backslash if needed
            }
            for (int i = 0; i < text.length(); i++) {
                char currentChar = text.charAt(i);
                switch (currentChar) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case ',':
                    sb.append("\\,");
                    break;
                case '+':
                    sb.append("\\+");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '<':
                    sb.append("\\<");
                    break;
                case '>':
                    sb.append("\\>");
                    break;
                case ';':
                    sb.append("\\;");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                default:
                    sb.append(currentChar);
                }
            }
            if ((text.length() > 1) && (text.charAt(text.length() - 1) == ' ')) {
                sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if needed
            }
            if (log.isDebugEnabled()) {
                log.debug("value after escaping special characters in " + text + " : " + sb.toString());
            }
            return sb.toString();
        } else {
            return text;
        }

    }

    /**
     * @param dn UserDn or Search base.
     * @return String with escape charaters removed.
     */
    private String escapeDNForSearch(String dn) {
        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = userStoreProperties
                .get(CommonConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }
        if (replaceEscapeCharacters) {
            return dn.replace("\\\\", "\\\\\\").replace("\\\"", "\\\\\"");
        } else {
            return dn;
        }
    }

    /**
     * @param dnPartial String with * as regex whoes escape characters should be removed.
     * @return String with escape characters removed.
     */
    private String escapeSpecialCharactersForFilterWithStarAsRegex(String dnPartial) {
        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = userStoreProperties
                .get(CommonConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < dnPartial.length(); i++) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                case '\\':
                    if (dnPartial.charAt(i + 1) == '*') {
                        sb.append("\\2a");
                        i++;
                        break;
                    }
                    sb.append("\\5c");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(currentChar);
                }
            }
            return sb.toString();
        } else {
            return dnPartial;
        }
    }

    /**
     * @return true if the Referral in the userstore-mgt.xml is "ignore". false otherwise.
     */
    private boolean isIgnorePartialResultException() {

        return PROPERTY_REFERRAL_IGNORE.equals(userStoreProperties.get(LDAPConstants.PROPERTY_REFERRAL));
    }

    /**
     * @param userName Username of the user.
     * @param searchBase Search base group search base.
     * @return List of roles of the given user.
     * @throws UserStoreException If an error occurs while retrieving data from LDAP userstore.
     */
    private String[] getLDAPRoleListOfUser(String userName, String searchBase) throws UserStoreException {
        boolean debug = log.isDebugEnabled();
        List<String> list;

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        // Load normal roles with the user
        String searchFilter;
        String roleNameProperty;
        searchFilter = userStoreProperties.get(LDAPConstants.GROUP_NAME_LIST_FILTER);
        roleNameProperty =
                userStoreProperties.get(LDAPConstants.GROUP_NAME_ATTRIBUTE);

        String membershipProperty =
                userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
        String userDNPattern = userStoreProperties.get(LDAPConstants.USER_DN_PATTERN);
        String nameInSpace;
        if (userDNPattern != null && userDNPattern.trim().length() > 0
                && !userDNPattern.contains(CommonConstants.XML_PATTERN_SEPERATOR)) {

            nameInSpace = MessageFormat.format(userDNPattern, escapeSpecialCharactersForDN(userName));
        } else {
            nameInSpace = this.getNameInSpaceForUserName(userName);
        }

        String membershipValue;
        if (nameInSpace != null) {
            try {
                LdapName ldn = new LdapName(nameInSpace);
                if (MEMBER_UID.equals(userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE))) {
                    // membership value of posixGroup is not DN of the user
                    List rdns = ldn.getRdns();
                    membershipValue = ((Rdn) rdns.get(rdns.size() - 1)).getValue().toString();
                } else {
                    membershipValue = escapeLdapNameForFilter(ldn);
                }
            } catch (InvalidNameException e) {
                log.error("Error while creating LDAP name from: " + nameInSpace);
                throw new UserStoreException(
                        "Invalid naming org.wso2.carbon.identity.agent.outbound.exception for : " + nameInSpace, e);
            }
        } else {
            return new String[0];
        }

        searchFilter =
                "(&" + searchFilter + "(" + membershipProperty + "=" + membershipValue + "))";
        String returnedAtts[] = { roleNameProperty };
        searchCtls.setReturningAttributes(returnedAtts);

        if (debug) {
            log.debug("Reading roles with the membershipProperty Property: " + membershipProperty);
        }

        list = this.getListOfNames(searchBase, searchFilter, searchCtls, roleNameProperty);

        String[] result = list.toArray(new String[list.size()]);

        for (String rolename : result) {
            log.debug("Found role: " + rolename);
        }
        return result;
    }

    /**
     * @param searchBases Group search bases.
     * @param searchFilter Search filter for role search with membership value included.
     * @param searchCtls Search controls with returning attributes set.
     * @param property Role name attribute name in LDAP userstore.
     * @return List of roles according to the given filter.
     * @throws UserStoreException If an error occurs while retrieving data from LDAP context.
     */
    private List<String> getListOfNames(String searchBases, String searchFilter,
            SearchControls searchCtls, String property)
            throws UserStoreException {
        boolean debug = log.isDebugEnabled();
        List<String> names = new ArrayList<>();
        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;

        if (debug) {
            log.debug("Result for searchBase: " + searchBases + " searchFilter: " + searchFilter +
                    " property:" + property);
        }

        try {
            dirContext = connectionSource.getContext();

            // handle multiple search bases
            String[] searchBaseArray = searchBases.split(CommonConstants.XML_PATTERN_SEPERATOR);
            for (String searchBase : searchBaseArray) {

                try {
                    answer = dirContext.search(escapeDNForSearch(searchBase), searchFilter, searchCtls);

                    while (answer.hasMoreElements()) {
                        SearchResult sr = answer.next();
                        if (sr.getAttributes() != null) {
                            Attribute attr = sr.getAttributes().get(property);
                            if (attr != null) {
                                for (Enumeration vals = attr.getAll(); vals.hasMoreElements(); ) {
                                    String name = (String) vals.nextElement();
                                    if (debug) {
                                        log.debug("Found user: " + name);
                                    }
                                    names.add(name);
                                }
                            }
                        }
                    }
                } catch (NamingException e) {
                    // ignore
                    if (log.isDebugEnabled()) {
                        log.debug(e);
                    }
                }

                if (debug) {
                    for (String name : names) {
                        log.debug("Result  :  " + name);
                    }
                }

            }

            return names;
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }
    }

    /**
     * This method escapes the special characters in a LdapName
     * according to the ldap filter escaping standards.
     * @param ldn LDAP name which the special characters should be escaped.
     * @return - LDAP name with special characters removed.
     */
    private String escapeLdapNameForFilter(LdapName ldn) {

        if (ldn == null) {
            if (log.isDebugEnabled()) {
                log.debug("Received null value to escape special characters. Returning null");
            }
            return null;
        }

        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = userStoreProperties
                .get(CommonConstants.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if (replaceEscapeCharacters) {
            StringBuilder escapedDN = new StringBuilder();
            for (int i = ldn.size() - 1; i > -1; i--) { //escaping the rdns separately and re-constructing the DN
                escapedDN = escapedDN.append(escapeSpecialCharactersForFilterWithStarAsRegex(ldn.get(i)));
                if (i != 0) {
                    escapedDN.append(",");
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Escaped DN value for filter : " + escapedDN);
            }
            return escapedDN.toString();
        } else {
            return ldn.toString();
        }
    }

    /**
     * Reused method to search groups with various filters.
     *
     * @param searchFilter Group Search Filter
     * @param returningAttributes Attributes which the values needed.
     * @param searchScope Search Scope
     * @return Group Representation with given returning attributes
     */
    protected NamingEnumeration<SearchResult> searchInGroupBase(String searchFilter,
            String[] returningAttributes,
            int searchScope,
            DirContext rootContext,
            String searchBase)
            throws UserStoreException {
        SearchControls userSearchControl = new SearchControls();
        userSearchControl.setReturningAttributes(returningAttributes);
        userSearchControl.setSearchScope(searchScope);
        NamingEnumeration<SearchResult> groupSearchResults = null;
        try {
            groupSearchResults = rootContext.search(escapeDNForSearch(searchBase), searchFilter, userSearchControl);
        } catch (NamingException e) {
            String errorMessage = "Error occurred while searching in group base.";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
        return groupSearchResults;
    }

    /**
     * Check whether this is the last/only user in this group.
     *
     * @param userDN DN of the User.
     * @param groupEntry SearchResult Representing the Group.
     * @return true if user is the only one in role, false otherwise.
     */
    protected boolean isOnlyUserInRole(String userDN, SearchResult groupEntry)
            throws UserStoreException {
        boolean isOnlyUserInRole = false;
        try {
            Attributes groupAttributes = groupEntry.getAttributes();
            if (groupAttributes != null) {
                NamingEnumeration attributes = groupAttributes.getAll();
                while (attributes.hasMoreElements()) {
                    Attribute memberAttribute = (Attribute) attributes.next();
                    String memberAttributeName = userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
                    String attributeID = memberAttribute.getID();
                    if (memberAttributeName.equals(attributeID)) {
                        if (memberAttribute.size() == 1 && userDN.equals(memberAttribute.get())) {
                            return true;
                        }
                    }

                }

                attributes.close();

            }
        } catch (NamingException e) {
            String errorMessage = "Error occurred while looping through attributes set of group: "
                    + groupEntry.getNameInNamespace();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
        return isOnlyUserInRole;
    }

    /**
     * Either delete or add user from/to group.
     *
     * @param userNameDN : distinguish name of user entry.
     * @param groupRDN   : relative distinguish name of group entry
     * @param modifyType : modify attribute type in DirCOntext.
     * @throws UserStoreException If an error occurs while updating.
     */
    protected void modifyUserInRole(String userNameDN, String groupRDN, int modifyType, String searchBase)
            throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Modifying role: " + groupRDN + " with type: " + modifyType + " user: " + userNameDN
                    + " in search base: " + searchBase);
        }

        DirContext mainDirContext = null;
        DirContext groupContext = null;
        try {
            mainDirContext = this.connectionSource.getContext();
            groupContext = (DirContext) mainDirContext.lookup(searchBase);
            String memberAttributeName = userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
            Attributes modifyingAttributes = new BasicAttributes(true);
            Attribute memberAttribute = new BasicAttribute(memberAttributeName);
            memberAttribute.add(userNameDN);
            modifyingAttributes.put(memberAttribute);

            groupContext.modifyAttributes(groupRDN, modifyType, modifyingAttributes);
            if (log.isDebugEnabled()) {
                log.debug("User: " + userNameDN + " was successfully " + "modified in LDAP group: "
                        + groupRDN);
            }
        } catch (NamingException e) {
            String errorMessage = "Error occurred while modifying user entry: " + userNameDN
                    + " in LDAP role: " + groupRDN;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage);
        } finally {
            JNDIUtil.closeContext(groupContext);
            JNDIUtil.closeContext(mainDirContext);
        }
    }

    /**
     * Check whether user is in the group by searching through its member attributes.
     *
     * @param userDN DN of the User whose existence in the group is searched.
     * @param groupEntry SearchResult representation of the Group.
     * @return true if the user exists in the role, false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    protected boolean isUserInRole(String userDN, SearchResult groupEntry)
            throws UserStoreException {
        boolean isUserInRole = false;
        try {
            Attributes groupAttributes = groupEntry.getAttributes();
            if (groupAttributes != null) {
                // get group's returned attributes
                NamingEnumeration attributes = groupAttributes.getAll();
                // loop through attributes
                while (attributes.hasMoreElements()) {
                    Attribute memberAttribute = (Attribute) attributes.next();
                    String memberAttributeName = userStoreProperties.get(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
                    if (memberAttributeName.equalsIgnoreCase(memberAttribute.getID())) {
                        // loop through attribute values
                        for (int i = 0; i < memberAttribute.size(); i++) {
                            if (userDN.equalsIgnoreCase((String) memberAttribute.get(i))) {
                                return true;
                            }
                        }
                    }

                }
                attributes.close();
            }
        } catch (NamingException e) {
            String errorMessage = "Error occurred while looping through attributes set of group: "
                    + groupEntry.getNameInNamespace();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
        return isUserInRole;
    }

    public String getUserStoreDomain() {
        return userStoreProperties.get(LDAPConstants.DOMAIN_NAME);
    }
}
