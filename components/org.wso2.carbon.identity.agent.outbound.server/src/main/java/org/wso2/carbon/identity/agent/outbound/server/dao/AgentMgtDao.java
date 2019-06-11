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
package org.wso2.carbon.identity.agent.outbound.server.dao;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.agent.outbound.server.SQLQueries;
import org.wso2.carbon.identity.agent.outbound.server.util.DatabaseUtil;
import org.wso2.carbon.identity.user.store.common.UserStoreConstants;
import org.wso2.carbon.identity.user.store.common.model.AgentConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Token management data access object
 */
public class AgentMgtDao {

    private static final Logger LOGGER = LoggerFactory.getLogger(AgentMgtDao.class);

    /**
     * Update agent connection information.
     * @param accessTokenId Access token ID
     * @param node Client node
     * @param serverNode Server node
     * @param status connection status (Ex. F=Failed, C=Connected)
     * @return result of the operation
     */
    public boolean updateConnection(int accessTokenId, String node, String serverNode, String status) {
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        boolean result = true;
        try {
            dbConnection = DatabaseUtil.getDBConnection();
            prepStmt = dbConnection.prepareStatement(SQLQueries.QUERY_UPDATE_AGENT_CONNECTIONS);
            prepStmt.setString(1, status);
            prepStmt.setString(2, serverNode);
            prepStmt.setInt(3, accessTokenId);
            prepStmt.setString(4, node);
            prepStmt.executeUpdate();
            DatabaseUtil.commitTransaction(dbConnection);
        } catch (SQLException e) {
            DatabaseUtil.rollbackTransaction(dbConnection);
            String errorMessage = "Error occurred while updating connection client node: " + node + " server node: " +
                    serverNode + " status: " + status;
            LOGGER.error(errorMessage, e);
            result = false;
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
        return result;
    }

    /**
     * Update all connections status which connected to particular servernode.
     * @param serverNode Server node
     * @param status Connection status
     * @return result of the operation
     */
    public boolean updateConnectionStatus(String serverNode, String status) {
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        boolean result = true;
        try {
            dbConnection = DatabaseUtil.getDBConnection();
            prepStmt = dbConnection.prepareStatement(SQLQueries.QUERY_UPDATE_AGENT_CONNECTIONS_STATUS);
            prepStmt.setString(1, status);
            prepStmt.setString(2, serverNode);
            prepStmt.executeUpdate();
            DatabaseUtil.commitTransaction(dbConnection);
        } catch (SQLException e) {
            DatabaseUtil.rollbackTransaction(dbConnection);
            String errorMessage = "Error occurred while updating connection status server node: " + serverNode;
            LOGGER.error(errorMessage, e);
            result = false;
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
        return result;
    }

    /**
     * Check is client node connected.
     * @param accessTokenId Access token ID
     * @param node Client node
     * @return result of the operation
     */
    public boolean isNodeConnected(int accessTokenId, String node) {
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        boolean isValid = false;
        try {
            dbConnection = DatabaseUtil.getDBConnection();
            prepStmt = dbConnection.prepareStatement(SQLQueries.QUERY_IS_AGENT_NODE_CONNECTED);
            prepStmt.setInt(1, accessTokenId);
            prepStmt.setString(2, node);
            prepStmt.setString(3, UserStoreConstants.CLIENT_CONNECTION_STATUS_CONNECTED);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                isValid = true;
            }
            DatabaseUtil.commitTransaction(dbConnection);
        } catch (SQLException e) {
            DatabaseUtil.rollbackTransaction(dbConnection);
            String errorMessage = "Error occurred while checking node connection node: " + node;
            LOGGER.error(errorMessage, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, resultSet, prepStmt);
        }
        return isValid;
    }

    /**
     * Returns the connected server's host / ip for the given node.
     *
     * @param accessTokenId Id of the access token
     * @param node Node hostname / ip
     * @return Connected server's host name / ip
     */
    public String getConnectedServer(int accessTokenId, String node) {

        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String serverNode = null;
        try {
            dbConnection = DatabaseUtil.getDBConnection();
            prepStmt = dbConnection.prepareStatement(SQLQueries.QUERY_GET_AGENT_SERVER_CONNECTED);
            prepStmt.setInt(1, accessTokenId);
            prepStmt.setString(2, node);
            prepStmt.setString(3, UserStoreConstants.CLIENT_CONNECTION_STATUS_CONNECTED);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                serverNode = resultSet.getString(1);
            }
            DatabaseUtil.commitTransaction(dbConnection);
        } catch (SQLException e) {
            DatabaseUtil.rollbackTransaction(dbConnection);
            String errorMessage = "Error occurred while checking server connected for : " + node;
            LOGGER.error(errorMessage, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, resultSet, prepStmt);
        }
        return serverNode;

    }

    /**
     * Check client connection is exist.
     * @param accessTokenId Access token ID
     * @param node client node
     * @return result of the operation
     */
    public boolean isConnectionExist(int accessTokenId, String node) {
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        boolean isExist = false;
        try {
            dbConnection = DatabaseUtil.getDBConnection();
            prepStmt = dbConnection.prepareStatement(SQLQueries.QUERY_IS_AGENT_CONNECTION_EXIST);
            prepStmt.setInt(1, accessTokenId);
            prepStmt.setString(2, node);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                isExist = true;
            }
            DatabaseUtil.commitTransaction(dbConnection);
        } catch (SQLException e) {
            DatabaseUtil.rollbackTransaction(dbConnection);
            String errorMessage = "Error occurred while checking connection node: " + node;
            LOGGER.error(errorMessage, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, resultSet, prepStmt);
        }
        return isExist;
    }

    /**
     * Add agent connection.
     * @param connection Agent connection model
     * @return result of the operation
     */
    public boolean addAgentConnection(AgentConnection connection) {
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        boolean result = true;
        try {
            dbConnection = DatabaseUtil.getDBConnection();
            prepStmt = dbConnection.prepareStatement(SQLQueries.QUERY_ADD_CONNECTION);
            prepStmt.setInt(1, connection.getAccessTokenId());
            prepStmt.setString(2, connection.getNode());
            prepStmt.setString(3, connection.getStatus());
            prepStmt.setString(4, connection.getServerNode());
            prepStmt.executeUpdate();
            DatabaseUtil.commitTransaction(dbConnection);
        } catch (SQLException e) {
            DatabaseUtil.rollbackTransaction(dbConnection);
            String errorMessage = "Error occurred while adding connection information.";
            LOGGER.error(errorMessage, e);
            result = false;
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
        return result;
    }

    /**
     * Get all agent connections
     * @param tenantDomain Tenant domain
     * @param domain User store domain
     * @param status connection status (Ex. F=Failed, C=Connected)
     * @return List of connections
     */
    public List<AgentConnection> getAgentConnections(String tenantDomain, String domain, String status) {
        Connection dbConnection = null;
        PreparedStatement insertTokenPrepStmt = null;
        ResultSet resultSet = null;
        List<AgentConnection> agentConnections = new ArrayList<>();
        try {
            dbConnection = DatabaseUtil.getDBConnection();
            insertTokenPrepStmt = dbConnection.prepareStatement(SQLQueries.QUERY_GET_ALL_CONNECTIONS);
            insertTokenPrepStmt.setString(1, status);
            insertTokenPrepStmt.setString(2, domain);
            insertTokenPrepStmt.setString(3, tenantDomain);
            resultSet = insertTokenPrepStmt.executeQuery();
            while (resultSet.next()) {
                AgentConnection agentConnection = new AgentConnection();
                agentConnection.setStatus(resultSet.getString("UM_STATUS"));
                agentConnection.setNode(resultSet.getString("UM_NODE"));
                agentConnection.setAccessTokenId(resultSet.getInt("UM_ACCESS_TOKEN_ID"));
                agentConnection.setServerNode(resultSet.getString("UM_SERVER_NODE"));
                agentConnections.add(agentConnection);
            }
            DatabaseUtil.commitTransaction(dbConnection);
        } catch (SQLException e) {
            DatabaseUtil.rollbackTransaction(dbConnection);
            String errorMessage = "Error occurred while reading agent connection information tenant: " +  tenantDomain +
                    " domain: " + domain + " status: " + status;
            LOGGER.error(errorMessage, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, resultSet, insertTokenPrepStmt);
        }
        return agentConnections;
    }

}
