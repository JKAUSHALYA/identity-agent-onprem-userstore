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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.agent.userstore.UserAgentConstants;
import org.wso2.carbon.identity.agent.userstore.config.UserStoreConfiguration;
import org.wso2.carbon.identity.agent.userstore.constant.CommonConstants;
import org.wso2.carbon.identity.agent.userstore.constant.XMLConfigurationConstants;
import org.wso2.carbon.identity.agent.userstore.exception.UserStoreException;

import java.io.File;
import java.util.Map;
import java.util.TreeMap;

/**
 *  Creates an instance of the Relevant UserStoreManager.
 */
public class UserStoreManagerBuilder {
    private static Logger log = LoggerFactory.getLogger(UserStoreManagerBuilder.class);
    private static volatile Map<String, UserStoreManager> userStoreManagers = null;

    /**
     * @return Initialize an instance of the UserStoreManager according to the given userstore config file
     * @throws UserStoreException If an error occurs while loading the class or instantiating it.
     */
    private static UserStoreManager initializeUserStoreManager(String userStoreConfigPath) throws UserStoreException {
        UserStoreConfiguration configuration = new UserStoreConfiguration(userStoreConfigPath);
        Map<String, String> userStoreProperties = configuration.getUserStoreProperties();
        try {
            Class managerClass = UserStoreManagerBuilder.class.getClassLoader().
                    loadClass(userStoreProperties.get(XMLConfigurationConstants.LOCAL_NAME_CLASS));
            UserStoreManager userStoreManager = (UserStoreManager) managerClass.newInstance();
            userStoreManager.setUserStoreProperties(userStoreProperties);
            return userStoreManager;
        } catch (ClassNotFoundException e) {
            String message = "Error while loading the UserStoreManager";
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            throw new UserStoreException(message, e);
        } catch (InstantiationException e) {
            String message = "Error instantiating the UserStoreManager because, " +
                    "Class represents an abstract class, an interface, an array class, " +
                    "a primitive type, or void; or the class has no nullary constructor; " +
                    "or for some other reason.";
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            throw new UserStoreException(message, e);
        } catch (IllegalAccessException e) {
            String message = userStoreProperties.get(XMLConfigurationConstants.LOCAL_NAME_CLASS) +
                    " Class or its nullary constructor is not accessible";
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            throw new UserStoreException(message, e);
        }
    }

    /**
     * Reads the user store configuration files at <code>conf/userstores</code> and loads them as
     * {@link UserStoreManager} objects into a Map sorted by User Store Domain Name
     * @throws UserStoreException if an exception occurs while loading the user stores
     */
    private static void loadUserStores() throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Loading user stores ...");
        }
        userStoreManagers = new TreeMap<>();
        String configDir = System.getProperty(CommonConstants.CARBON_HOME) +  File.separator
                + UserAgentConstants.AGENT_CONFIG_DIRECTORY + File.separator
                + UserAgentConstants.USER_STORE_CONFIG_DIRECTORY;

        File[] listOfFiles = new File(configDir).listFiles();
        if (listOfFiles != null) {
            for (File file : listOfFiles) {
                if (log.isDebugEnabled()) {
                    log.debug("Initializing user store from file : " + file.getPath());
                }
                UserStoreManager userStoreManager = initializeUserStoreManager(file.getAbsolutePath());
                if (userStoreManagers.containsKey(userStoreManager.getUserStoreDomain())) {
                    log.error("An UserStore exists with the same Domain Name : "
                            + userStoreManager.getUserStoreDomain() + ". Hence ignoring the user store config file : "
                            + file.getAbsolutePath());
                } else {
                    userStoreManagers.put(userStoreManager.getUserStoreDomain(), userStoreManager);
                }
            }
        } else {
            String message = "No user store configuration files found. At lease one user store configuration " +
                    "file should be present";
            throw new UserStoreException(message);
        }

    }

    /**
     * Returns a map of {@link UserStoreManager} with the Domain Name as the Key
     * @return A map of {@link UserStoreManager} with the Domain Name as the Key
     * @throws UserStoreException if an exception occurs while loading the user stores
     */
    public static Map<String, UserStoreManager> getUserStoreManagers() throws UserStoreException {
        if (userStoreManagers == null) {
            synchronized (UserStoreManagerBuilder.class) {
                if (userStoreManagers == null) {
                    loadUserStores();
                }
            }
        }
        return userStoreManagers;
    }

    /**
     * Returns a {@link UserStoreManager} object which corresponds to the user store that the given user is a member of
     * from the map of User Stores which is sorted by the Domain name
     * @param username the username
     * @return a {@link UserStoreManager} object which corresponds to the user store that the given user is a member of
     * @throws UserStoreException if an exception occurs when checking the user existence
     */
    public static UserStoreManager getUserStoreManager(String username) throws UserStoreException {
        for (UserStoreManager userStoreManager : userStoreManagers.values()) {
            if (log.isDebugEnabled()) {
                log.debug("Searching for user in user store with domain : " + userStoreManager.getUserStoreDomain());
            }
            if (userStoreManager.doCheckExistingUser(username)) {
                if (log.isDebugEnabled()) {
                    log.debug("User found in user store with domain : " + userStoreManager.getUserStoreDomain());
                }
                return userStoreManager;
            }
        }
        return null;
    }
}
