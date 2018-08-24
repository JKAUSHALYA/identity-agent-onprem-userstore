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

package org.wso2.carbon.identity.agent.userstore.util;

import org.wso2.carbon.identity.agent.userstore.config.AgentConfigUtil;
import org.wso2.carbon.identity.agent.userstore.constant.CommonConstants;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Contains Functionalities common to all types of UserStoreManagers.
 */
public class UserStoreUtils {

    /**
     * @param userName Username of the User
     * @param displayName Display Name if provided
     * @return Combined User Name
     */
    public static String getCombinedName(String userName, String displayName) {
    /*
     * get the name in combined format if two different values are there for userName &
     * displayName format: userName|displayName
     */
        String combinedName = null;
        if (!userName.equals(displayName) && displayName != null) {
            combinedName = userName + CommonConstants.NAME_COMBINER + displayName;
        } else {
            combinedName = userName;
        }
        return combinedName;
    }

    public static String getUserStoreAwareUsername(String username) {
        String tenantDomain = AgentConfigUtil.build().getTenantDomain();
        if (username.contains("@") &&
                tenantDomain.equals(username.substring(username.indexOf("@") + 1))) {
            username = username.substring(0, username.indexOf(tenantDomain) - 1);
        }
        return username;
    }

    /**
     * Combines two String Arrays eliminating duplicates
     * @param arr1 Array 1
     * @param arr2 Array 2
     * @return combined array
     */
    public static String[] combineArrays(String[] arr1, String[] arr2) {
        if (arr1 == null || arr1.length == 0) {
            return arr2;
        }
        if (arr2 == null || arr2.length == 0) {
            return arr1;
        }

        Set<String> stringSet = new HashSet<>();
        stringSet.addAll(Arrays.asList(arr1));
        stringSet.addAll(Arrays.asList(arr2));

        return stringSet.toArray(new String[0]);
    }
}
