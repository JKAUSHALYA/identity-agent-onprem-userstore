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
import org.wso2.carbon.identity.user.store.common.model.AccessToken;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Token management data access object
 */
public class TokenMgtDao {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenMgtDao.class);

    /**
     * Get access token.
     * @param accessToken Access token
     * @return Access token model
     */
    public AccessToken getAccessToken(String accessToken) {
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            dbConnection = DatabaseUtil.getDBConnection();
            prepStmt = dbConnection.prepareStatement(SQLQueries.QUERY_GET_ACCESS_TOKEN);
            prepStmt.setString(1, accessToken);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                AccessToken token = new AccessToken();
                token.setAccessToken(resultSet.getString("UM_TOKEN"));
                token.setId(resultSet.getInt("UM_ID"));
                token.setTenant(resultSet.getString("UM_TENANT"));
                token.setDomain(resultSet.getString("UM_DOMAIN"));
                token.setStatus(resultSet.getString("UM_STATUS"));
                return token;
            }
            dbConnection.commit();
        } catch (SQLException e) {
            DatabaseUtil.rollbackTransaction(dbConnection);
            String errorMessage = "Error occurred while validating access token";
            LOGGER.error(errorMessage, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, resultSet, prepStmt);
        }
        return null;
    }

}
