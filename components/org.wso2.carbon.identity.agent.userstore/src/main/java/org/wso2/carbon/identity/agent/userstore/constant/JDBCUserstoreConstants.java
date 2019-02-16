package org.wso2.carbon.identity.agent.userstore.constant;

/**
 * JDBC Userstore Constants
 */
public class JDBCUserstoreConstants {

    public static final String DOMAIN_NAME = "DomainName";
    public static final String DRIVER_NAME = "DriverName";
    public static final String CONNECTION_URL = "ConnectionURL";
    public static final String JDBC_USERNAME = "Username";
    public static final String JDBC_PASSWORD = "Password";
    public static final String SQL_VALIDATION_QUERY = "ValidationQuery";
    public static final String SELECT_USER = "SelectUserSQL";
    public static final String STORE_SALTED_PASSWORDS = "StoreSaltedPassword";
    public static final String DIGEST_FUNCTION = "PasswordDigest";
    public static final String PASSWORD_HASH_METHOD_PLAIN_TEXT = "PLAIN_TEXT";
    public static final String PROPERTY_MAX_USER_AND_ROLE_LIST_LENGTH = "MaxListLength";
    public static final int DEFAULT_MAX_VALUE = 100;
    public static final int MAX_SEARCH_TIME = 10000;   // ms
    public static final String GET_USER_FILTER = "UserFilterSQL";
    public static final String GET_ROLE_LIST = "GetRoleListSQL";
    public static final String PROPERTY_MAX_SEARCH_TIME = "MaxSearchQueryTime";
    public static final String GET_USER_ROLE = "UserRoleSQL";
    public static final String GET_IS_USER_EXISTING = "IsUserExistingSQL";
    public static final String USER_NAME_UNIQUE = "UserNameUniqueSQL";
    public static final String GET_USERS_IN_ROLE = "GetUserListOfRoleSQL";
    public static final String GET_IS_ROLE_EXISTING = "IsRoleExistingSQL";
    public static final String GET_USER_ATTRIBUTES = "GetUserAttributesSQL";
}
