#!/bin/bash

# Execute Junit tests for ACE and save as Jacoco test reports

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

# If indicated install Mysql server
if [ "$1" = "--with-mysql" ]
then
  echo "mysql-server mysql-server/root_password password root" | sudo debconf-set-selections
  echo "mysql-server mysql-server/root_password_again password root" | sudo debconf-set-selections
  sudo apt-get -y install mysql-server
  sudo systemctl start mysql.service
  echo "root" > ace/db.pwd # Root username
  echo "root" >> ace/db.pwd # Root pw
fi

# Run ACE JUnit tests
# https://stackoverflow.com/questions/65092032/maven-build-failed-but-exit-code-is-still-0
cd ace
echo "*** Building and running ACE JUnit tests ***"
mvn clean org.jacoco:jacoco-maven-plugin:0.8.6:prepare-agent install org.jacoco:jacoco-maven-plugin:0.8.6:report | tee mvn_res
if grep 'BUILD FAILURE' mvn_res;then exit 1; fi;
if grep 'BUILD SUCCESS' mvn_res;then exit 0; else exit 1; fi;
rm mvn_res
cd ..

