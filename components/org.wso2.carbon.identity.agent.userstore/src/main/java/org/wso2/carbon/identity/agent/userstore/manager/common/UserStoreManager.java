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

package org.wso2.carbon.identity.agent.userstore.manager.common;

import org.wso2.carbon.identity.agent.userstore.exception.UserStoreException;

import java.util.Map;

/**
 * Base userstore org.wso2.carbon.identity.agent.outbound.manager.
 */
public interface UserStoreManager {

    /**
     * @param userName Username of the user
     * @param claimUris Array of required attributes' names
     * @return Map containing the name value pairs of required attributes
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    Map<String, String> getUserClaimValues(String userName, String[] claimUris) throws UserStoreException;

    /**
     * @param userName Username of the user
     * @param credential Password of the user
     * @return true if the users credentials are valid. false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    boolean doAuthenticate(String userName, Object credential) throws UserStoreException;

    /**
     * @param filter Username filter String.
     * @param maxItemLimit Maximum size of the username list.
     * @return The list of usernames.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException;

    /**
     * @param filter Group filter string
     * @param maxItemLimit Maximum size of the return group list
     * @return The array of all the group names
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException;

    /**
     * @param userName Username of the user whose role list is required.
     * @return The array of roles of the given user.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    String[] doGetExternalRoleListOfUser(String userName) throws UserStoreException;

    /**
     * @return true if the connection to the userstore is healthy. false otherwise.
     */
    boolean getConnectionStatus() throws UserStoreException;

    /**
     * @param userName Username of the user whose existence is to be checked.
     * @return true if the user existes in userstore. false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    boolean doCheckExistingUser(String userName) throws UserStoreException;

    /**
     * @param userName Username of the user whose existence in role to be checked.
     * @param roleName Name of the Role which the user is checked to be in.
     * @return true if the user is in the role. false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException;

    /**
     * @param roleName Name of the Role which users in the list should belong.
     * @return Array of usernames of the Users in given role.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    String[] doGetUserListOfRole(String roleName, int maxItemLimit) throws UserStoreException;

    /**
     * @param roleName Name of the Role which the existance is checked.
     * @return true if a role exists in given name. false otherwise.
     * @throws UserStoreException If an error occurs while retrieving data.
     */
    boolean doCheckExistingRole(String roleName) throws UserStoreException;

    /**
     * @param userName Username of the user whose role list is updated.
     * @param deletedRoles List of names of roles that the user is removed from.
     * @param newRoles List of names of new roles that the user is added to.
     * @throws UserStoreException If an error occurs while updting the role list.
     */
    void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles) throws UserStoreException;

    /**
     * @param userStoreProperties Properties read from the userstore-mgt.xml file.
     * @throws UserStoreException If a required attribute of the UserStoreManager is missing.
     */
    void setUserStoreProperties(Map<String, String> userStoreProperties) throws UserStoreException;

    /**
     * Returns the Domain name of the user store
     * @return Domain Name of the user store
     */
    String getUserStoreDomain();
}
