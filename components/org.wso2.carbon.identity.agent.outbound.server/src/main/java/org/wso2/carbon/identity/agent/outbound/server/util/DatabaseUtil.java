/*
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.agent.outbound.server.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.tomcat.jdbc.pool.PoolProperties;
import org.wso2.carbon.identity.agent.outbound.server.model.DatabaseConfig;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.sql.DataSource;

/**
 * Database utility
 */
public class DatabaseUtil {

    private static Log log = LogFactory.getLog(DatabaseUtil.class);
    private static DataSource jdbcds = loadUserStoreSpacificDataSoruce();

    /**
     * Returns an database connection for Identity data source.
     *
     * @return dbConnection
     * @throws SQLException
     * @Deprecated The getDBConnection should handle both transaction and non-transaction connection. Earlier it
     * handle only the transactionConnection. Therefore this method was deprecated and changed as handle both
     * transaction and non-transaction connection. getDBConnection(boolean shouldApplyTransaction) method used as
     * alternative of this method.
     */
    @Deprecated
    public static Connection getDBConnection() throws SQLException {

        return getDBConnection(true);
    }

    /**
     * Get database connection.
     * @return SQL connection
     * @throws SQLException
     */
    public static Connection getDBConnection(boolean shouldApplyTransaction) throws SQLException {

        Connection dbConnection = getJDBCDataSource().getConnection();
        if (shouldApplyTransaction) {
            dbConnection.setAutoCommit(false);
            if (dbConnection.getTransactionIsolation() != java.sql.Connection.TRANSACTION_READ_COMMITTED) {
                dbConnection.setTransactionIsolation(java.sql.Connection.TRANSACTION_READ_COMMITTED);
            }
        }
        return dbConnection;
    }

    /**
     * Get JDBC data source.
     * @return datasource
     */
    private static DataSource getJDBCDataSource() {
        if (jdbcds == null) {
            jdbcds = loadUserStoreSpacificDataSoruce();
        }
        return jdbcds;
    }

    /**
     * Load user store properties from config and create datasource.
     * @return datasource
     */
    private static DataSource loadUserStoreSpacificDataSoruce() {
        DatabaseConfig dbConf = ServerConfigurationBuilder.build().getDatabase();
        PoolProperties poolProperties = new PoolProperties();
        poolProperties.setDriverClassName(dbConf.getDriver());
        poolProperties.setUrl(dbConf.getUrl());
        poolProperties.setUsername(dbConf.getUsername());
        poolProperties.setPassword(dbConf.getPassword());
        poolProperties.setTestOnBorrow(Boolean.parseBoolean(dbConf.getTestonborrow()));
        poolProperties.setValidationQuery(dbConf.getValidationquery());

        return new org.apache.tomcat.jdbc.pool.DataSource(poolProperties);
    }

    /**
     * Close DB connection
     * @param dbConnection sql connection
     */
    public static void closeConnection(Connection dbConnection) {

        if (dbConnection != null) {
            try {
                dbConnection.close();
            } catch (SQLException e) {
                log.error("Database error. Could not close statement. Continuing with others. - " + e.getMessage(), e);
            }
        }
    }

    /**
     * Close resultset.
     * @param rs SQL resultset
     */
    private static void closeResultSet(ResultSet rs) {

        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException e) {
                log.error("Database error. Could not close result set  - " + e.getMessage(), e);
            }
        }
    }

    /**
     * Close prepaedstatement.
     * @param preparedStatement SQL preparedstatememt
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
     * Close number of prepared statement.
     * @param prepStmts all prepaired statements
     */
    private static void closeStatements(PreparedStatement... prepStmts) {

        if (prepStmts != null && prepStmts.length > 0) {
            for (PreparedStatement stmt : prepStmts) {
                closeStatement(stmt);
            }
        }
    }

    /**
     * Close all sql connections and prepared statements
     * @param dbConnection sql connection
     * @param prepStmts prepairedstatements
     */
    public static void closeAllConnections(Connection dbConnection, PreparedStatement... prepStmts) {

        closeStatements(prepStmts);
        closeConnection(dbConnection);
    }

    /**
     * Close all sql connections, resultset and prepared statements
     * @param dbConnection sql connection
     * @param rs resultset
     * @param prepStmts all prepaired statements
     */
    public static void closeAllConnections(Connection dbConnection, ResultSet rs, PreparedStatement... prepStmts) {

        closeResultSet(rs);
        closeStatements(prepStmts);
        closeConnection(dbConnection);
    }

    public static void closeAllConnections(Connection dbConnection, ResultSet rs1, ResultSet rs2,
            PreparedStatement... prepStmts) {
        closeResultSet(rs1);
        closeResultSet(rs1);
        closeStatements(prepStmts);
        closeConnection(dbConnection);
    }

    /**
     * Revoke the transaction when catch then sql transaction errors.
     *
     * @param dbConnection Database connection.
     */
    public static void rollbackTransaction(Connection dbConnection) {

        try {
            if (dbConnection != null) {
                dbConnection.rollback();
            }
        } catch (SQLException e1) {
            log.error("An error occurred while rolling back transactions. ", e1);
        }
    }

    /**
     * Commit the transaction.
     *
     * @param dbConnection database connection.
     */
    public static void commitTransaction(Connection dbConnection) {

        try {
            if (dbConnection != null) {
                dbConnection.commit();
            }
        } catch (SQLException e1) {
            log.error("An error occurred while commit transactions. ", e1);
        }
    }
}
