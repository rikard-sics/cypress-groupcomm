#!/bin/bash

# Builds standalone Jar files for the EDHOC Applications
# Phase0Client: CoAP-only client
# Phase1Server: EDHOC server using method 0 and no optimized request
# Phase1Client: EDHOC client using method 0 and no optimized request
# Phase2Server: EDHOC server using method 3 and no optimized request
# Phase2Client: EDHOC client using method 3 and no optimized request
# Phase3Server: EDHOC server using method 0 and the optimized request
# Phase3Client: EDHOC client using method 0 and the optimized request
# Phase4Server: EDHOC server using method 3 and the optimized request
# Phase4Client: EDHOC client using method 3 and the optimized request

# Fail script with error if any command fails
set -e

# Build Californium (if needed)
FILE1=californium-extended/cf-oscore/target/cf-oscore-3.1.0-SNAPSHOT.jar
FILE2=californium-extended/californium-core/target/californium-core-3.1.0-SNAPSHOT.jar
FILE3=californium-extended/scandium-core/target/scandium-3.1.0-SNAPSHOT.jar
FILE4=californium-extended/element-connector/target/element-connector-3.1.0-SNAPSHOT.jar
FILE5=californium-extended/cf-edhoc/target/cf-edhoc-3.1.0-SNAPSHOT.jar
if [[ -f "$FILE1" ]] && [[ -f "$FILE2" ]] && [[ -f "$FILE3" ]] && [[ -f "$FILE4" ]] && [[ -f "$FILE5" ]]; then
    echo "Dependencies from Californium exist."
else 
    echo "Dependencies from Californium missing. Building Californium..."
    cd californium-extended
    mvn -DskipTests clean install
    cd ..
fi

# Prepare dependencies from Californium
mvn install:install-file -Dfile=californium-extended/cf-oscore/target/cf-oscore-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=cf-oscore \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=edhoc-applications/local-maven-repo

mvn install:install-file -Dfile=californium-extended/californium-core/target/californium-core-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=californium-core \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=edhoc-applications/local-maven-repo

mvn install:install-file -Dfile=californium-extended/scandium-core/target/scandium-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=scandium \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=edhoc-applications/local-maven-repo

mvn install:install-file -Dfile=californium-extended/element-connector/target/element-connector-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=element-connector \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=edhoc-applications/local-maven-repo

mvn install:install-file -Dfile=californium-extended/cf-edhoc/target/cf-edhoc-3.1.0-SNAPSHOT.jar \
                         -DgroupId=org.eclipse.californium \
                         -DartifactId=cf-edhoc \
                         -Dversion=3.1.0-SNAPSHOT \
                         -Dpackaging=jar \
                         -DlocalRepositoryPath=edhoc-applications/local-maven-repo

# Build standalone Jar files
cd edhoc-applications
echo "*** Building EDHOC Applications ***"
mkdir -p lib

# Servers
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase1Server" -DjarName="Phase1Server"
mv target/Phase1Server.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase2Server" -DjarName="Phase2Server"
mv target/Phase2Server.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase3Server" -DjarName="Phase3Server"
mv target/Phase3Server.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase4Server" -DjarName="Phase4Server"
mv target/Phase4Server.jar .

# Clients
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase0Client" -DjarName="Phase0Client"
mv target/Phase0Client.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase1Client" -DjarName="Phase1Client"
mv target/Phase1Client.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase2Client" -DjarName="Phase2Client"
mv target/Phase2Client.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase3Client" -DjarName="Phase3Client"
mv target/Phase3Client.jar .
mvn clean package -Dfully.qualified.main.class="se.sics.edhocapps.Phase4Client" -DjarName="Phase4Client"
mv target/Phase4Client.jar .

# Run EDHOC Apps JUnit tests
# https://stackoverflow.com/questions/65092032/maven-build-failed-but-exit-code-is-still-0
mvn clean org.jacoco:jacoco-maven-plugin:0.8.6:prepare-agent install org.jacoco:jacoco-maven-plugin:0.8.6:report | tee mvn_res
if grep 'BUILD FAILURE' mvn_res;then exit 1; fi;
if grep 'BUILD SUCCESS' mvn_res;then echo "BUILD SUCCESS"; else exit 1; fi;
rm mvn_res

rm -rf local-maven-repo

echo "Jar files containing EDHOC Applications built under edhoc-applications/. Execute them with lib in the same folder. Use -help to see possible arguments when applicable."

