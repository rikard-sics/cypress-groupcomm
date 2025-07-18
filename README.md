[![coverage-edhoc](https://rikard-sics.github.io/cypress-groupcomm/reports/jacoco-edhoc.svg 'Code Coverage: EDHOC')](https://rikard-sics.github.io/cypress-groupcomm/reports/edhoc/)
[![coverage-oscore](https://rikard-sics.github.io/cypress-groupcomm/reports/jacoco-oscore.svg 'Code Coverage: OSCORE & Group OSCORE')](https://rikard-sics.github.io/cypress-groupcomm/reports/oscore/)
[![coverage-ace](https://rikard-sics.github.io/cypress-groupcomm/reports/jacoco-ace.svg 'Code Coverage: ACE & Group Joining')](https://rikard-sics.github.io/cypress-groupcomm/reports/ace/)

## CYPRESS secure group communication codebase

Joint codebase for CYPRESS including ACE, EDHOC, OSCORE, Group OSCORE, and Group Joining (plus associated things).

### Building and importing

1. Run the `config.sh` script

1.5. Set the correct maven profile as described below.

2. Start Eclipse, then import the following projects:
  
    - californium-extended
    - ace
    - group-applications
    - edhoc-applications

3. To "ace" add the following folders to the build path:

    - californium-core
    - cf-oscore
    - element-connector
    - scandium

4. To "group-applications" add the following folders to the build path:
    - ace
    - californium-core
    - cf-oscore
    - element-connector
    - scandium

5. To "edhoc-applications" add the following folders to the build path:
    - californium-core
    - cf-edhoc
    - cf-oscore
    - element-connector

To add dependencies:

*Right click project->Properties->Java Build Path->Add...*

### Select Maven profile

If you are developing in Eclipse (and possibly other IDEs) choose the "eclipse" Maven profile for ACE:

*Right click on "ace"->Maven->Select Maven Profile...* (CTRL+Alt+P)

Deactive the "default" profile, and activate the "eclipse" profile.

*Right click on "group-applications->Maven->Select Maven Profile...* (CTRL+Alt+P)

Deactive the "default" profile, and activate the "eclipse" profile.

*Right click on "edhoc-applications"->Maven->Select Maven Profile...* (CTRL+Alt+P)

Deactive the "default" profile, and activate the "eclipse" profile.


### MySQL installation

Note that MySQL is needed for the ACE parts to run correctly. To install it use:
```
sudo apt-get install mysql-server
```

Then place a file under ace/db.pwd and group-applications/db.pwd with the database root password.


### Updating the JCE (Java Cryptography Extensions)

If some of the JUnit tests fail due to "invalid key size" you may need to update the JCE. In such case follow these instructions:

https://www.andreafortuna.org/2016/06/08/java-tips-how-to-fix-the-invalidkeyexception-illegal-key-size-or-default-parameters-runtime/


### Repository content overview

- config.sh
    - Configure and prepare projects for import in Eclipse

- test-californium.sh
    - Execute JUnit tests for Californium and save as Jacoco test reports

- test-ace.sh
    - Execute JUnit tests for ACE and save as Jacoco test reports
    - Specify the flag --with-mysql to also perform install and setup of MySQL server

- build-group-apps.sh
    - Builds standalone Jar files for the Group Applications

- build-edhoc-apps.sh
    - Builds standalone Jar files for the EDHOC Applications

- build-for-docker.sh
    - Prepares Docker Dockerfiles and Contexts for the Group & EDHOC Applications
    - If the flag --build-images is specified, it also builds the Docker images

- code-coverage.sh
    - Relocate Jacoco code coverage reports for deployment to gh-pages

- californium-extended/
    - Modified version of the Californium CoAP library with support for EDHOC and Group OSCORE

- ace/
    - Implementation of ACE with support for Group Managers and the Group Joining procedure

- group-applications/
    - **The Group Applications including:**
    - OscoreAsServer: ACE Authorization Server
    - OscoreRsServer: Group Manager (ACE Resource Server)
    - OscoreAsRsClient: Group OSCORE Server/Client which will join the group(s)
    - Adversary: Adversary for testing attacks against the group(s)
    
      **See separate README under *group-applications/* for more detailed information**

- edhoc-applications/
    - **The EDHOC Applications including:**
    - Phase0Client: CoAP-only client
    - Phase1Server: EDHOC server using method 0 and no optimized request
    - Phase1Client: EDHOC client using method 0 and no optimized request
    - Phase2Server: EDHOC server using method 3 and no optimized request
    - Phase2Client: EDHOC client using method 3 and no optimized request
    - Phase3Server: EDHOC server using method 0 and the optimized request
    - Phase3Client: EDHOC client using method 0 and the optimized request
    - Phase4Server: EDHOC server using method 3 and the optimized request
    - Phase4Client: EDHOC client using method 3 and the optimized request

      **See separate README under *edhoc-applications/* for more detailed information**

### Code coverage reports

Automatic code coverage reports are generated with Jacoco and can be found at the following links:

[EDHOC](https://rikard-sics.github.io/cypress-groupcomm/reports/edhoc/) (californium-extended/cf-edhoc)

[OSCORE & Group OSCORE](https://rikard-sics.github.io/cypress-groupcomm/reports/oscore/) (californium-extended/cf-oscore)

[ACE & Group Joining](https://rikard-sics.github.io/cypress-groupcomm/reports/ace/) (ace)

