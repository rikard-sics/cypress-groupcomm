#!/bin/bash

# Execute Junit tests for Californium and save as Jacoco test reports

# Fail script with error if any command fails
set -e

# https://stackoverflow.com/questions/65092032/maven-build-failed-but-exit-code-is-still-0
cd californium-extended
echo "*** Building and running Californium JUnit tests ***"
mvn clean org.jacoco:jacoco-maven-plugin:0.8.6:prepare-agent install org.jacoco:jacoco-maven-plugin:0.8.6:report | tee mvn_res
if grep 'BUILD FAILURE' mvn_res;then exit 1; fi;
if grep 'BUILD SUCCESS' mvn_res;then exit 0; else exit 1; fi;
rm mvn_res
cd ..

