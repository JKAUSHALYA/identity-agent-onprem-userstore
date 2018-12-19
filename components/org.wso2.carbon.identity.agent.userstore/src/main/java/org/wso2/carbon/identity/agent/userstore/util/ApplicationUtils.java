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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

/**
 *  Used to get org.wso2.carbon.identity.agent.outbound.Application properties.
 */
public class ApplicationUtils {
    private static final String PROCESS_FILE_NAME = "wso2agent.pid";
    private static Logger log = LoggerFactory.getLogger(ApplicationUtils.class);

    public static String getProductHomePath() {
        return System.getProperty("user.dir");
    }

    /**
     * Write the process ID of this process to wso2agent.pid file.
     */
    public static void writePID() {

        String[] cmd = {"bash", "-c", "echo $PPID"};
        Process process;
        String pid = "";
        try {
            process = Runtime.getRuntime().exec(cmd);
        } catch (IOException e) {
            //Ignored. We might be invoking this on a Window platform. Therefore if an error occurs
            //we simply ignore the error.
            return;
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line);
            }
            pid = builder.toString();
        } catch (IOException e) {
            log.error("Error while retrieving the process ID. ", e);
        }

        if (pid.length() != 0) {
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(Paths.get(getProductHomePath(), PROCESS_FILE_NAME).toString()),
                    StandardCharsets.UTF_8))) {
                writer.write(pid);
            } catch (IOException e) {
                log.error("Cannot write process ID to " + PROCESS_FILE_NAME + " file.", e);
            }
        }
    }
}
