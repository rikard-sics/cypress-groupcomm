#!/bin/bash

# Builds DHT-enabled standalone Jar files for the Group Applications
# OscoreAsServer: ACE Authorization Server
# OscoreRsServer: Group Manager
# OscoreAsRsClient: Group OSCORE Server/Client which will join the group(s)
# Adversary: Adversary for testing attacks against the group(s)

# Fail script with error if any command fails
set -e

# Build Californium (if needed)
FILE1=californium-extended/cf-oscore/target/cf-oscore-3.1.0-SNAPSHOT.jar
FILE2=californium-extended/californium-core/target/californium-core-3.1.0-SNAPSHOT.jar
FILE3=californium-extended/scandium-core/target/scandium-3.1.0-SNAPSHOT.jar
FILE4=californium-extended/element-connector/target/element-connector-3.1.0-SNAPSHOT.jar
if [[ -f "$FILE1" ]] && [[ -f "$FILE2" ]] && [[ -f "$FILE3" ]] && [[ -f "$FILE4" ]]; then
    echo "Dependencies from Californium exist."
else 
    echo "Dependencies from Californium missing. Building Californium..."
    cd californium-extended
    mvn -DskipTests clean install
    cd ..
fi

# Build ACE (if needed)
FILE=ace/target/ace-0.0.1-SNAPSHOT.jar
if [ -f "$FILE" ]; then
    echo "$FILE exists."
else 
    echo "$FILE does not exist. Building ACE..."
    
    # Prepare dependencies from Californium for ACE
    mvn install:install-file -Dfile=californium-extended/cf-oscore/target/cf-oscore-3.1.0-SNAPSHOT.jar \
                             -DgroupId=org.eclipse.californium \
                             -DartifactId=cf-oscore \
                             -Dversion=3.1.0-SNAPSHOT \
                             -Dpackaging=jar \
                             -DlocalRepositoryPath=ace/local-maven-repo

    mvn install:install-file -Dfile=californium-extended/californium-core/target/californium-core-3.1.0-SNAPSHOT.jar \
                             -DgroupId=org.eclipse.californium \
                             -DartifactId=californium-core \
                             -Dversion=3.1.0-SNAPSHOT \
                             -Dpackaging=jar \
                             -DlocalRepositoryPath=ace/local-maven-repo

    mvn install:install-file -Dfile=californium-extended/scandium-core/target/scandium-3.1.0-SNAPSHOT.jar \
                             -DgroupId=org.eclipse.californium \
                             -DartifactId=scandium \
                             -Dversion=3.1.0-SNAPSHOT \
                             -Dpackaging=jar \
                             -DlocalRepositoryPath=ace/local-maven-repo

    mvn install:install-file -Dfile=californium-extended/element-connector/target/element-connector-3.1.0-SNAPSHOT.jar \
                             -DgroupId=org.eclipse.californium \
                             -DartifactId=element-connector \
                             -Dversion=3.1.0-SNAPSHOT \
                             -Dpackaging=jar \
                             -DlocalRepositoryPath=ace/local-maven-repo

    cd ace
    mvn -DskipTests clean install
    cd ..
fi

# Prepare dependencies from Californium and ACE
mvn install:install-file -Dfile=californium-extended/cf-oscore/target/cf-oscore-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=cf-oscore \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=group-applications/local-maven-repo

mvn install:install-file -Dfile=californium-extended/californium-core/target/californium-core-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=californium-core \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=group-applications/local-maven-repo

mvn install:install-file -Dfile=californium-extended/scandium-core/target/scandium-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=scandium \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=group-applications/local-maven-repo

mvn install:install-file -Dfile=californium-extended/element-connector/target/element-connector-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=element-connector \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=group-applications/local-maven-repo

mvn install:install-file -Dfile=ace/target/ace-0.0.1-SNAPSHOT.jar \
                         -DgroupId=se.sics \
                         -DartifactId=ace \
                         -Dversion=0.0.1-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=group-applications/local-maven-repo

# Build standalone Jar files
cd group-applications
echo "*** Building Group Applications ***"
mkdir -p lib

mvn clean package -Dfully.qualified.main.class="se.sics.prototype.apps.OscoreAsServer" -DjarName="OscoreAsServer"
mv target/OscoreAsServer.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.prototype.apps.OscoreRsServer" -DjarName="OscoreRsServer"
mv target/OscoreRsServer.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.prototype.apps.OscoreAsRsClient" -DjarName="OscoreAsRsClient"
mv target/OscoreAsRsClient.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.prototype.apps.Adversary" -DjarName="Adversary"
mv target/Adversary.jar .

# Run Group Apps JUnit tests
# https://stackoverflow.com/questions/65092032/maven-build-failed-but-exit-code-is-still-0
mvn clean org.jacoco:jacoco-maven-plugin:0.8.6:prepare-agent install org.jacoco:jacoco-maven-plugin:0.8.6:report | tee mvn_res
if grep 'BUILD FAILURE' mvn_res;then exit 1; fi;
if grep 'BUILD SUCCESS' mvn_res;then echo "BUILD SUCCESS"; else exit 1; fi;
rm mvn_res

rm -rf local-maven-repo

echo "Note: A MySQL server must be installed with the root username & password indicated in db.pwd in the folder the Jars are launched from"
echo "Jar files containing Group Applications built under group-applications/. Execute them with lib in the same folder. Use -help to see possible arguments when applicable."

