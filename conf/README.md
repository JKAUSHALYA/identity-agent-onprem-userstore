# WSO2 On-premise Outbound User Store Agent
WSO2 On-premise Outbound User Store Agent is a lightweight MSF4J (WSO2 Microservices Framework for Java) service which is used by the WSO2 Identity Cloud to connect to the on-premise userstores.

## Key Features
*  Authenticate users in LDAP userstore.
*  Retrieve attributes of users in LDAP userstore.
*  Retrieve roles of a user in LDAP userstore.
*  Secure configuration files through Ciphertool.

## System Requirements
1. Minimum memory - 512MB
2. Processor - Pentium 800MHz or equivalent at minimum
3. Java SE Development Kit 1.8
4. To build WSO2 On Premise Agent from the Source, it is also necessary that you have Maven 3 or later.

## Project Resources
* Forums : http://stackoverflow.com/questions/tagged/wso2/
* WSO2 Developer List: dev@wso2.org

## Installation and Running
1. Extract the downloaded zip file
2. Configure the userstores/userstore-mgt.xml file with the values relevant to your on premise user store.
3. Run the wso2agent.sh file.
4. When agent start enter installation token created while configuring directory.

## WSO2 On Premise User Store Agent Directory Structure
 
        CARBON_HOME
        ├── lib
        ├── conf  
        │   ├── security
            ├── userstores
        
        
     - lib
       Contains the jar files for the agent and the ciphertool
  
     - conf
       Contains all the configuration files needed for the MSF4J configuration 
       and ciphertool configurations.
          
          - security
            Contains the keystore file and configuration files related to security.
          - userstores
            Contains the userstore configuration file(s)            
            
### Securing sensitive information in configuration files.
There are sensitive information such as passwords in the configuration. You can secure them by using secure vault. 
Please go through following steps to secure them.

  1. Configure secure vault with default configurations by running ciphertool script from CARBON_HOME directory.
    `ciphertool.sh` (in UNIX)
    
This script would do following configurations that you need to do by manually

(i)   Replaces sensitive elements in configuration files, that have been defined in cipher-tool.properties, with alias token       values.
(ii)  Encrypts plain text password which is defined in cipher-text.properties file.
(iii) Updates secret-conf.properties file with default keystore and callback class.   

cipher-tool.properties, cipher-text.properties and secret-conf.properties files can be found at conf/security directory.

For more details see http://docs.wso2.org/wiki/display/Carbon420/WSO2+Carbon+Secure+Vault

## Support
We are committed to ensuring that your enterprise middleware deployment is completely supported from evaluation to production. Our unique approach ensures that all support leverages our open development methodology and is provided by the very same engineers who build the technology.

For more details and to take advantage of this unique opportunity, visit http://wso2.com/support/.

For more information on WSO2 Carbon, visit the WSO2 Oxygen Tank (http://wso2.org)

____

(c) Copyright 2017 WSO2 Inc.
