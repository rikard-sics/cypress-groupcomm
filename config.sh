#!/bin/bash

# Configure and prepare projects for import in Eclipse

cd ace
mvn -P eclipse eclipse:eclipse
cd ..

cd californium-extended
mvn eclipse:eclipse
cd ..

cd group-applications
mvn -P eclipse eclipse:eclipse
cd ..

cd edhoc-applications
mvn -P eclipse eclipse:eclipse
cd ..

#Check that the ace/db.pwd file exists
FILE=ace/db.pwd
if [ ! -f "$FILE" ]; then
 echo
 echo "Warning: File ace/db.pwd is missing!"
 echo
fi

#Check that the group-applications/db.pwd file exists
FILE=group-applications/db.pwd
if [ ! -f "$FILE" ]; then
 echo
 echo "Warning: File group-applications/db.pwd is missing!"
 echo
fi

