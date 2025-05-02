#!/bin/bash

# Compile Jacoco code coverage reports
echo "*** Collecting Jacoco code coverage reports ***"

mkdir -p jacoco/ace
cp -r ace/target/site/jacoco/* jacoco/ace/

mkdir -p jacoco/oscore
cp -r californium-extended/cf-oscore/target/site/jacoco/* jacoco/oscore/

mkdir -p jacoco/edhoc
cp -r californium-extended/cf-edhoc/target/site/jacoco/* jacoco/edhoc/

