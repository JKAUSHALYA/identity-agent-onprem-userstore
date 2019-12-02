/*
 * Copyright (c) 2016, WSO2 Inc. (http://wso2.com) All Rights Reserved.
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
package org.wso2.carbon.identity.agent.userstore.config;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.agent.userstore.constant.XMLConfigurationConstants;
import org.wso2.carbon.identity.agent.userstore.exception.UserStoreException;
import org.wso2.carbon.identity.agent.userstore.exception.XMLException;
import org.wso2.carbon.identity.agent.userstore.util.XMLUtils;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;
import org.wso2.securevault.commons.MiscellaneousUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

/**
 *  Process XML files and retrieve properties.
 */
class UserStoreConfigurationXMLProcessor {

    private static Logger log = LoggerFactory.getLogger(UserStoreConfigurationXMLProcessor.class);
    private InputStream inStream = null;
    private SecretResolver secretResolver;

    /**
     * @return The Map of user store properties
     */
    Map<String, String> buildUserStoreConfigurationFromFile(String path) throws UserStoreException {
        OMElement rootElement;
        Map<String, String> properties;
        try {
            rootElement = getRootElement(path);
            properties = buildUserStoreConfiguration(rootElement);

            if (inStream != null) {
                inStream.close();
            }
        } catch (UserStoreException e) {
            String message = "Error while reading userstore configuration from file";
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            throw new UserStoreException(message, e);
        } catch (IOException e) {
            String message = "Error while closing the input stream";
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            throw new UserStoreException(message, e);
        } catch (XMLStreamException e) {
            String message = "Error while validating the XML file";
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            throw new UserStoreException(message, e);
        }
        return properties;
    }

    /**
     * @param rootElement The root OMElement of the XML file
     * @return The map of user store properties
     */
    private Map<String, String> buildUserStoreConfiguration(OMElement rootElement) throws UserStoreException {
        String userStoreClass;
        Map<String, String> map = new HashMap<>();
        userStoreClass = rootElement.getAttributeValue(new QName(XMLConfigurationConstants.LOCAL_NAME_CLASS));
        if (userStoreClass == null || userStoreClass.isEmpty()) {
            String message = "Mandatory Property UserStoreManager Class is not set";
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new UserStoreException(message);
        }
        map.put(XMLConfigurationConstants.LOCAL_NAME_CLASS, userStoreClass);
        Iterator<?> ite = rootElement.getChildrenWithName(new QName(
                XMLConfigurationConstants.LOCAL_NAME_PROPERTY));
        while (ite.hasNext()) {
            OMElement propElem = (OMElement) ite.next();
            String propName = propElem.getAttributeValue(new QName(
                    XMLConfigurationConstants.ATTR_NAME_PROP_NAME));
            String propValue;
            String resolvedPropValue = MiscellaneousUtil.resolve(propElem, secretResolver);
            if (resolvedPropValue != null && !resolvedPropValue.isEmpty()) {
                propValue = resolvedPropValue;
            } else {
                propValue = propElem.getText();
            }
            map.put(propName.trim(), propValue.trim());
        }
        return map;
    }

    /**
     * @param userStoreConfigPath Path to the configuration file
     * @return The <Configuration> element of the given file.
     * @throws javax.xml.stream.XMLStreamException If an error occurs in building the XML configurations.
     * @throws java.io.IOException If the file does not exist, is a directory rather than a regular file,
     * or for some other reason cannot be opened for reading.
     * @throws UserStoreException If the inputStream is null or cannot validate the XML file.
     */
    private OMElement getRootElement(String userStoreConfigPath) throws XMLStreamException, IOException,
            UserStoreException {
        OMXMLParserWrapper builder;

        File profileConfigXml = new File(userStoreConfigPath);
        if (profileConfigXml.exists()) {

            inStream = new FileInputStream(profileConfigXml);
        }

        if (inStream == null) {
            String message = "Profile configuration not found.";
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new FileNotFoundException(message);
        }
        try {
            inStream = XMLUtils.replaceSystemVariablesInXml(inStream);
        } catch (XMLException e) {
            throw new UserStoreException(e.getMessage(), e);
        }

        builder = new StAXOMBuilder(inStream);
        OMElement rootElement = builder.getDocumentElement();
        setSecretResolver(rootElement);
        return rootElement;
    }

    /**
     * @param rootElement The root OMElement of the XML file
     */
    private void setSecretResolver(OMElement rootElement) {
        secretResolver = SecretResolverFactory.create(rootElement, true);
    }
}
