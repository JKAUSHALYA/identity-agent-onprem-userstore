package org.wso2.carbon.identity.agent.userstore.manager.jdbc;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.tomcat.jdbc.pool.PoolProperties;
import org.wso2.carbon.identity.agent.userstore.config.ClaimConfiguration;
import org.wso2.carbon.identity.agent.userstore.constant.JDBCUserstoreConstants;
import org.wso2.carbon.identity.agent.userstore.constant.LDAPConstants;
import org.wso2.carbon.identity.agent.userstore.exception.UserStoreException;
import org.wso2.carbon.identity.agent.userstore.manager.common.UserStoreManager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.sql.DataSource;

/**
 *  User Store org.wso2.carbon.identity.agent.outbound.manager for JDBC user stores.
 */
public class JDBCUserStoreManager implements UserStoreManager {
    private static Log log = LogFactory.getLog(JDBCUserStoreManager.class);
    protected DataSource jdbcds = null;
    private Map<String, String> userStoreProperties = null;

    public JDBCUserStoreManager() {
    }

    public JDBCUserStoreManager(Map<String, String> userStoreProperties)
            throws UserStoreException {
        // check if required configurations are in the user-mgt.xml
        checkRequiredUserStoreConfigurations();
        this.userStoreProperties = userStoreProperties;
        log.info("Initialized the on premise JDBC userstore manager");
    }

    /**
     * This method retrieves the attributes corresponding to the claim values from the database.
     * @param userName  Username of the user
     * @param claimUris Array of required attributes' names
     * @return Map containing the name value pairs of required attributes
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public Map<String, String> getUserClaimValues(String userName, String[] claimUris) throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Getting the user claim values from the database for the user " + userName);
        }
        Connection dbConnection = null;
        ResultSet resultSet = null;
        PreparedStatement prepStmt = null;
        String sqlStmt = null;
        Map<String, String> values = new HashMap<>();
        try {
            dbConnection = getDBConnection();

            if (dbConnection == null) {
                throw new UserStoreException("The database connection is empty");
            }
            sqlStmt = this.userStoreProperties.get(JDBCUserstoreConstants.GET_USER_ATTRIBUTES);

            if (log.isDebugEnabled()) {
                log.debug(sqlStmt);
            }

            prepStmt = dbConnection.prepareStatement(sqlStmt);
            prepStmt.setString(1, userName);
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String attributeName = resultSet.getString(1);
                String attributeValue = resultSet.getString(2);
                if (attributeValue == null) {
                    attributeValue = "";
                }
                values.put(attributeName, attributeValue);
            }
        } catch (SQLException e) {
            String message = "Error occurred while retrieving user attribute info.";
            log.error(message, e);
            throw new UserStoreException("Error retrieving user claims");
        } finally {
            closeAllConnections(dbConnection, resultSet, prepStmt);
        }

        Map<String, String> claimValues = new HashMap<>();
        Map<String, String> claimMap = ClaimConfiguration.getConfiguration().getClaimMap();
        for (String claim : claimUris) {
            Optional<String> value = Optional.ofNullable(values.get(claimMap.get(claim)));
            value.ifPresent(s -> claimValues.put(claim, s));
        }

        return claimValues;
    }


    /**
     * Method is used to authenticate the user against the JDBC on premise userstore.
     * @param userName   Username of the user
     * @param credential Password of the user
     * @return true if the users credentials are valid. false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Starting authenticating the user " + userName + " against the JDBC userstore.");
        }
        Connection dbConnection = null;
        ResultSet resultSet = null;
        PreparedStatement prepStmt = null;
        String sqlStmt = null;
        String password = (String) credential;
        boolean isAuthed = false;
        try {
            dbConnection = getDBConnection();
            if (dbConnection == null) {
                throw new UserStoreException("The database connection is empty");
            }
            sqlStmt = this.userStoreProperties.get(JDBCUserstoreConstants.SELECT_USER);

            if (log.isDebugEnabled()) {
                log.debug(sqlStmt);
            }

            prepStmt = dbConnection.prepareStatement(sqlStmt);
            prepStmt.setString(1, userName);

            resultSet = prepStmt.executeQuery();

            if (resultSet.next() == true) {
                String storedPassword = resultSet.getString(1);
                String saltValue = null;
                if ("true".equalsIgnoreCase
                        (this.userStoreProperties.get(JDBCUserstoreConstants.STORE_SALTED_PASSWORDS))) {
                    saltValue = resultSet.getString(2);
                }

                password = this.preparePassword(password, saltValue);
                if ((storedPassword != null) && (storedPassword.equals(password))) {
                    isAuthed = true;
                }
            }
        } catch (SQLException e) {
            String message = "Error occurred while retrieving user authentication info.";
            log.error(message, e);
            throw new UserStoreException("Authentication Failure");
        } finally {
            closeAllConnections(dbConnection, resultSet, prepStmt);
        }

        if (log.isDebugEnabled()) {
            log.debug("User " + userName + " login attempt. Login success :: " + isAuthed);
        }

        return isAuthed;
    }

    /**
     * Method is used to list users in the jdbc userstore
     * @param filter       Username filter String.
     * @param maxItemLimit Maximum size of the username list.
     * @return The list of usernames.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Listing all users from the database with the filter " + filter);
        }
        String[] users = new String[0];
        Connection dbConnection = null;
        String sqlStmt = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        if (maxItemLimit == 0) {
            return new String[0];
        }

        try {
            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> userList = new LinkedList<String>();
            dbConnection = getDBConnection();

            if (dbConnection == null) {
                throw new UserStoreException("The database connection is empty");
            }

            sqlStmt = this.userStoreProperties.get(JDBCUserstoreConstants.GET_USER_FILTER);
            if (log.isDebugEnabled()) {
                log.debug(sqlStmt);
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);
            prepStmt.setString(1, filter);
            setMaxLimit(prepStmt, maxItemLimit);
            try {
                resultSet = prepStmt.executeQuery();
            } catch (SQLException e) {
                String message = "Error occurred while retrieving users for filter : " + filter
                        + " & max Item limit : " + maxItemLimit;
                log.error(message, e);
                throw new UserStoreException(message, e);
            }

            while (resultSet.next()) {
                String name = resultSet.getString(1);
                userList.add(name);
            }
            resultSet.close();

            if (userList.size() > 0) {
                users = userList.toArray(new String[userList.size()]);
            }
            Arrays.sort(users);
        } catch (SQLException e) {
            String message = "An error occurred while retrieving users.";
            log.error(message, e);
            throw new UserStoreException(message, e);
        } finally {
            closeAllConnections(dbConnection, resultSet, prepStmt);
        }
        return users;
    }

    /**
     * Method used to list roles from the JDBC userstore.
     * @param filter       Group filter string
     * @param maxItemLimit Maximum size of the return group list
     * @return The array of all the group names
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Listing all roles from the database with the filter " + filter);
        }
        String[] roles = new String[0];
        Connection dbConnection = null;
        String sqlStmt = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        if (maxItemLimit == 0) {
            return roles;
        }

        try {

            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<String>();

            dbConnection = getDBConnection();

            if (dbConnection == null) {
                throw new UserStoreException("The database connection is empty");
            }

            sqlStmt = this.userStoreProperties.get(JDBCUserstoreConstants.GET_ROLE_LIST);
            if (log.isDebugEnabled()) {
                log.debug(sqlStmt);
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);
            prepStmt.setString(1, filter);
            setMaxLimit(prepStmt, maxItemLimit);
            try {
                resultSet = prepStmt.executeQuery();
            } catch (SQLException e) {
                String message =
                        "Error while fetching roles from JDBC user store according to filter : " + filter +
                                " & max item limit : " + maxItemLimit;
                log.error(message, e);
                throw new UserStoreException(message, e);
            }

            if (resultSet != null) {
                while (resultSet.next()) {
                    String name = resultSet.getString(1);
                    lst.add(name);
                }
            }
            if (lst.size() > 0) {
                roles = lst.toArray(new String[lst.size()]);
            }

        } catch (SQLException e) {
            String message = "Error occurred while retrieving role names.";
            log.error(message, e);
            throw new UserStoreException(message, e);
        } finally {
            closeAllConnections(dbConnection, resultSet, prepStmt);
        }
        return roles;
    }

    /**
     * Method is used to get the roles of a given user
     * @param userName Username of the user whose role list is required.
     * @return The array of roles of the given user.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public String[] doGetExternalRoleListOfUser(String userName) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Getting roles of the user " + userName);
        }
        String[] roleNames = new String[0];
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Connection dbConnection = null;

        try {
            dbConnection = getDBConnection();
            if (dbConnection == null) {
                throw new UserStoreException("The database connection is empty");
            }
            String sqlStmt = this.userStoreProperties.get(JDBCUserstoreConstants.GET_USER_ROLE);
            if (log.isDebugEnabled()) {
                log.debug(sqlStmt);
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);
            if (userName != null) {
                prepStmt.setString(1, userName);
            } else {
                String message = "The userName name has not been specified for the doGetExternalRoleListOfUser method";
                log.error(message);
                throw new UserStoreException(message);
            }
            resultSet = prepStmt.executeQuery();
            List<String> roleList = new ArrayList<String>();
            while (resultSet.next()) {
                String role = resultSet.getString(1);
                roleList.add(role);
            }
            if (roleList.size() > 0) {
                roleNames = roleList.toArray(new String[roleList.size()]);
            }
        } catch (SQLException e) {
            String message = "Error occurred while retrieving string values.";
            log.error(message, e);
            throw new UserStoreException(message, e);
        } finally {
            closeAllConnections(dbConnection, resultSet, prepStmt);
        }
        if (log.isDebugEnabled()) {
            if (roleNames != null) {
                for (String name : roleNames) {
                    log.debug("Found role: " + name);
                }
            } else {
                log.debug("No external role found for the user: " + userName);
            }
        }

        return roleNames;
    }


    /**
     * Method checks if the user is an existing user
     * @param userName Username of the user whose existence is to be checked.
     * @return true if the user existes in userstore. false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public boolean doCheckExistingUser(String userName) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Checking the existence of the user " + userName);
        }
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        boolean isExisting = false;
        int value = -1;
        Connection dbConnection = null;

        String sqlStmt = this.userStoreProperties.get(JDBCUserstoreConstants.GET_IS_USER_EXISTING);
        if (log.isDebugEnabled()) {
            log.debug(sqlStmt);
        }
        try {
            dbConnection = getDBConnection();
            if (dbConnection == null) {
                throw new UserStoreException("The database connection is empty");
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);
            prepStmt.setString(1, userName);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                value = resultSet.getInt(1);
            }
            if (value > -1) {
                isExisting = true;
            }
        } catch (SQLException e) {
            String message = "An error occurred while checking the user existence in the database";
            log.error(message, e);
            throw new UserStoreException(message);
        } finally {
            closeAllConnections(dbConnection, resultSet, prepStmt);
        }

        return isExisting;
    }

    /**
     * Method checks if the user is in the given role
     * @param userName Username of the user whose existence in role to be checked.
     * @param roleName Name of the Role which the user is checked to be in.
     * @return true if the user is in the role. false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Checking if the user " + userName + " exists in the role " + roleName);
        }
        String[] roles = doGetExternalRoleListOfUser(userName);
        if (roles != null) {
            for (String role : roles) {
                if (role.equalsIgnoreCase(roleName)) {
                    return true;
                }
            }
        }

        return false;
    }


    /**
     * @param roleName     Name of the Role which users in the list should belong.
     * @param maxItemLimit
     * @return Array of usernames of the Users in given role.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public String[] doGetUserListOfRole(String roleName, int maxItemLimit) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Getting the list of users with the role " + roleName);
        }
        return getUserListOfJDBCRole(roleName, maxItemLimit);
    }


    /**
     * Method checks if the role exists
     * @param roleName Name of the Role which the existance is checked.
     * @return true if a role exists in given name. false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    @Override
    public boolean doCheckExistingRole(String roleName) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Checking the existence of the role " + roleName);
        }
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        boolean isExisting = false;
        int value = -1;
        Connection dbConnection = null;

        String sqlStmt = this.userStoreProperties.get(JDBCUserstoreConstants.GET_IS_ROLE_EXISTING);
        if (log.isDebugEnabled()) {
            log.debug(sqlStmt);
        }
        try {
            dbConnection = getDBConnection();
            if (dbConnection == null) {
                throw new UserStoreException("The database connection is empty");
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);
            prepStmt.setString(1, roleName);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                value = resultSet.getInt(1);
            }
            if (value > -1) {
                isExisting = true;
            }
        } catch (SQLException e) {
            String message = "An error occurred while checking the role existence in the database";
            log.error(message, e);
            throw new UserStoreException(message);
        } finally {
            closeAllConnections(dbConnection, resultSet, prepStmt);
        }

        return isExisting;
    }

    /**
     * This method retrieves the user list corresponding to a given role
     * @param roleName
     * @param maxItemLimit
     * @return
     * @throws UserStoreException
     */
    public String[] getUserListOfJDBCRole(String roleName, int maxItemLimit) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Getting the list of users in the role " + roleName);
        }
        String[] names = new String[0];
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Connection dbConnection = null;
        String sqlStmt = null;

        sqlStmt = this.userStoreProperties.get(JDBCUserstoreConstants.GET_USERS_IN_ROLE);
        if (log.isDebugEnabled()) {
            log.debug(sqlStmt);
        }

        try {
            List<String> userList = new ArrayList<String>();
            dbConnection = getDBConnection();
            if (dbConnection == null) {
                throw new UserStoreException("The database connection is empty");
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);
            if (roleName != null) {
                prepStmt.setString(1, roleName);
            } else {
                String message = "The role name has not been specified in the method getUserListOfJDBCRole";
                log.error(message);
                throw new UserStoreException(message);
            }
            if (maxItemLimit > 0) {
                prepStmt.setMaxRows(maxItemLimit);
            }
            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String name = resultSet.getString(1);
                userList.add(name);
            }
            if (userList.size() > 0) {
                names = userList.toArray(new String[userList.size()]);
            }
        } catch (SQLException e) {
            String message = "Error occurred while retrieving the user list for a given role.";
            log.error(message, e);
            throw new UserStoreException(message, e);
        } finally {
            closeAllConnections(dbConnection, resultSet, prepStmt);
        }
        return names;
    }

    /**
     * @param userName     Username of the user whose role list is updated.
     * @param deletedRoles List of names of roles that the user is removed from.
     * @param newRoles     List of names of new roles that the user is added to.
     * @throws UserStoreException If an error occurs while updting the role list.
     */
    @Override
    public void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles)
            throws UserStoreException {
    // Not needed to implement
    }

    /**
     * @param userStoreProperties Properties read from the userstore-mgt.xml file.
     * @throws UserStoreException If a required attribute of the UserStoreManager is missing.
     */
    @Override
    public void setUserStoreProperties(Map<String, String> userStoreProperties) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Setting the JDBC userstore properties");
        }
        this.userStoreProperties = userStoreProperties;
    }

    /**
     * Returns the Domain name of the user store
     *
     * @return Domain Name of the user store
     */
    @Override
    public String getUserStoreDomain() {
        if (log.isDebugEnabled()) {
            log.debug("Getting the userstore properties");
        }
        return userStoreProperties.get(JDBCUserstoreConstants.DOMAIN_NAME);
    }


    /**
     * Checks whether all the mandatory properties of user store are set.
     * @throws UserStoreException If any of the mandatory properties are not set in the userstore-mgt.xml.
     */
    private void checkRequiredUserStoreConfigurations() throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Checking JDBC configurations");
        }

        String domainName = userStoreProperties.get(LDAPConstants.DOMAIN_NAME);
        if (domainName == null || domainName.trim().length() == 0) {
            throw new UserStoreException(
                    "Required DomainName property is not set in the JDBC configurations");
        }

        String connectionURL = userStoreProperties.get(JDBCUserstoreConstants.CONNECTION_URL);

        if (connectionURL == null || connectionURL.trim().length() == 0) {
            throw new UserStoreException(
                    "Required ConnectionURL property is not set in the JDBC configurations");
        }
        String jdbcUsername = userStoreProperties.get(JDBCUserstoreConstants.JDBC_USERNAME);
        if (jdbcUsername == null || jdbcUsername.trim().length() == 0) {
            throw new UserStoreException(
                    "Required JDBC username property is not set in the JDBC configurations");
        }
        String jdbcPassword =
                userStoreProperties.get(JDBCUserstoreConstants.JDBC_PASSWORD);
        if (jdbcPassword == null || jdbcPassword.trim().length() == 0) {
            throw new UserStoreException(
                    "Required JDBC password property is not set in the JDBC configurations");
        }

        String sqlValidationQuery =
                userStoreProperties.get(JDBCUserstoreConstants.SQL_VALIDATION_QUERY);
        if (sqlValidationQuery == null || sqlValidationQuery.trim().length() == 0) {
            throw new UserStoreException(
                    "Required SQL validation query is not set in the JDBC configurations");
        }

        String selectUserQuery =
                userStoreProperties.get(JDBCUserstoreConstants.SELECT_USER);
        if (selectUserQuery == null || selectUserQuery.trim().length() == 0) {
            throw new UserStoreException(
                    "Required select user SQL query is not set in the JDBC configurations");
        }

        String getUserFilterSQL =
                userStoreProperties.get(JDBCUserstoreConstants.GET_USER_FILTER);
        if (getUserFilterSQL == null || getUserFilterSQL.trim().length() == 0) {
            throw new UserStoreException(
                    "Required get user filter SQL query is not set in the JDBC configurations");
        }

        String getRoleListQuery =
                userStoreProperties.get(JDBCUserstoreConstants.GET_ROLE_LIST);
        if (getRoleListQuery == null || getRoleListQuery.trim().length() == 0) {
            throw new UserStoreException(
                    "Required get role list SQL query is not set in the JDBC configurations");
        }

        String getUserRoleQuery =
                userStoreProperties.get(JDBCUserstoreConstants.GET_USER_ROLE);
        if (getUserRoleQuery == null || getUserRoleQuery.trim().length() == 0) {
            throw new UserStoreException(
                    "Required get users' role list SQL query is not set in the JDBC configurations");
        }

        String isUserExistingQuery =
                userStoreProperties.get(JDBCUserstoreConstants.GET_IS_USER_EXISTING);
        if (isUserExistingQuery == null || isUserExistingQuery.trim().length() == 0) {
            throw new UserStoreException(
                    " Required is user exists SQL query is not set in the JDBC configurations");
        }

        String usernameUniqueSQL =
                userStoreProperties.get(JDBCUserstoreConstants.USER_NAME_UNIQUE);
        if (usernameUniqueSQL == null || usernameUniqueSQL.trim().length() == 0) {
            throw new UserStoreException(
                    "Required is username unique SQL query is not set in the JDBC configurations");
        }

        String usersInRoleQuery =
                userStoreProperties.get(JDBCUserstoreConstants.GET_USERS_IN_ROLE);
        if (usersInRoleQuery == null || usersInRoleQuery.trim().length() == 0) {
            throw new UserStoreException(
                    "Required get users in role SQL query is not set in the JDBC configurations");
        }

        String isRoleExistingQuery =
                userStoreProperties.get(JDBCUserstoreConstants.GET_IS_ROLE_EXISTING);
        if (isRoleExistingQuery == null || isRoleExistingQuery.trim().length() == 0) {
            throw new UserStoreException(
                    "Required is role existing SQL query is not set in the JDBC configurations");
        }

        String getUserAttributesQuery =
                userStoreProperties.get(JDBCUserstoreConstants.GET_USER_ATTRIBUTES);
        if (usersInRoleQuery == null || usersInRoleQuery.trim().length() == 0) {
            throw new UserStoreException(
                    "Required get user attributes SQL query is not set in the JDBC configurations");
        }
    }

    /**
     * @return true if the connection to the userstore is healthy. false otherwise.
     */
    @Override
    public boolean getConnectionStatus() throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Getting the connection purpose");
        }
        try {
            getDBConnection();
        } catch (SQLException e) {
            String message = "An error occured while connecting to the database";
            log.error(message, e);
            throw new UserStoreException("Error in conecting!");
        }

        return true;
    }

    /**
     * @return
     * @throws UserStoreException
     */
    protected Connection getDBConnection() throws SQLException, UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Getting the JDBC database connection");
        }
        Connection dbConnection = getJDBCDataSource().getConnection();
        dbConnection.setAutoCommit(false);
        return dbConnection;
    }

    // Loading JDBC data store on demand.
    private DataSource getJDBCDataSource() throws SQLException, UserStoreException {
        if (jdbcds == null) {
            jdbcds = loadUserStoreSpecificDataSource(this.userStoreProperties);
        }
        return jdbcds;
    }

    /**
     * Load user store properties from config and create datasource.
     *
     * @return datasource
     */
    private static DataSource loadUserStoreSpecificDataSource(Map<String, String> userStoreProperties) {
        if (log.isDebugEnabled()) {
            log.debug("Loading the datasource properties");
        }
        PoolProperties poolProperties = new PoolProperties();
        poolProperties.setDriverClassName(userStoreProperties.get(JDBCUserstoreConstants.DRIVER_NAME));
        poolProperties.setUrl(userStoreProperties.get(JDBCUserstoreConstants.CONNECTION_URL));
        poolProperties.setUsername(userStoreProperties.get(JDBCUserstoreConstants.JDBC_USERNAME));
        poolProperties.setPassword(userStoreProperties.get(JDBCUserstoreConstants.JDBC_PASSWORD));
        poolProperties.setTestOnBorrow(false);
        poolProperties.setValidationQuery(userStoreProperties.get(JDBCUserstoreConstants.SQL_VALIDATION_QUERY));
        return new org.apache.tomcat.jdbc.pool.DataSource(poolProperties);
    }

    /**
     * Method closes the database connection
     * @param dbConnection current database connection
     */
    public static void closeConnection(Connection dbConnection) {

        if (dbConnection != null) {
            try {
                dbConnection.close();
            } catch (SQLException e) {
                log.error("Database error. Could not close database connection. " +
                        "Continuing with others. - " + e.getMessage(), e);
            }
        }
    }

    /**
     * Method closes the resultSet
     * @param resultSet
     */
    private static void closeResultSet(ResultSet resultSet) {

        if (resultSet != null) {
            try {
                resultSet.close();
            } catch (SQLException e) {
                log.error("Database error. Could not close result set  - " + e.getMessage(), e);
            }
        }

    }

    /**
     * Method closes the prepared statement
     *
     * @param preparedStatement
     */
    private static void closeStatement(PreparedStatement preparedStatement) {

        if (preparedStatement != null) {
            try {
                preparedStatement.close();
            } catch (SQLException e) {
                log.error("Database error. Could not close statement. Continuing with others. - " + e.getMessage(), e);
            }
        }

    }

    /**
     * Method closes the prepared statements
     * @param prepStmts
     */
    private static void closeStatements(PreparedStatement... prepStmts) {

        if (prepStmts != null && prepStmts.length > 0) {
            for (PreparedStatement stmt : prepStmts) {
                closeStatement(stmt);
            }
        }

    }

    /**
     * Method closes the open connections during the query execution against the JDBC userstore
     * @param dbConnection
     * @param resultSet
     * @param prepStmts
     */
    public static void closeAllConnections(Connection dbConnection,
                                           ResultSet resultSet, PreparedStatement... prepStmts) {

        closeResultSet(resultSet);
        closeStatements(prepStmts);
        closeConnection(dbConnection);
    }

    /**
     * Method is used to set the max number of rows to a prepared statement.
     * @param ps
     * @param maxItemLimit
     * @throws SQLException
     */
    private void setMaxLimit(PreparedStatement ps, int maxItemLimit) throws SQLException {

        int givenMax = JDBCUserstoreConstants.DEFAULT_MAX_VALUE;

        String maxUserAndRoleListLength =
                this.userStoreProperties.get(JDBCUserstoreConstants.PROPERTY_MAX_USER_AND_ROLE_LIST_LENGTH);
        if (maxUserAndRoleListLength != null || maxUserAndRoleListLength.trim().length() > 0) {
            givenMax = Integer.parseInt(maxUserAndRoleListLength);
        }

        if (maxItemLimit < 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }

        ps.setMaxRows(maxItemLimit);
    }

    /**
     * This constructs the password using the configured salt value(if any) and encryption algorithm.
     * If a plain text password has been used then it is returned as it is.
     * @param password
     * @param saltValue
     * @return
     * @throws UserStoreException
     */
    protected String preparePassword(String password, String saltValue) throws UserStoreException {
        try {
            String digestInput = password;
            if (saltValue != null) {
                digestInput = password + saltValue;
            }
            String digsestFunction = userStoreProperties.get(JDBCUserstoreConstants.DIGEST_FUNCTION);
            if (digsestFunction != null) {

                if (digsestFunction
                        .equals(JDBCUserstoreConstants.PASSWORD_HASH_METHOD_PLAIN_TEXT)) {
                    return password;
                }

                MessageDigest dgst = MessageDigest.getInstance(digsestFunction);
                byte[] byteValue = dgst.digest(digestInput.getBytes());
                password = Base64.encode(byteValue);
            }
            return password;
        } catch (NoSuchAlgorithmException e) {
            String message = "Error occurred while preparing the password.";
            log.error(message, e);
            throw new UserStoreException(message, e);
        }
    }
}
