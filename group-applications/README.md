**Codebase for CYPRESS including applications using OSCORE, Group OSCORE, ACE and Group Joining.**

To setup and run the provided applications, follow the steps below. This will start 3 clients and 1 server in one group, and 3 clients and 1 server in another group. The servers and clients all start by first requesting an ACE Token from the Authorization Server, then posting it to the Group Manager and performing the group join procedure. After that they are ready to securely communicate with Group OSCORE in the group.  

**Start the Group Manager**  
OscoreRsServer

**Next start the Authorization Server**  
OscoreAsServer

**Now start the server applications:**  
OscoreAsRsClient -name Server1  
OscoreAsRsClient -name Server2  
OscoreAsRsClient -name Server3  
OscoreAsRsClient -name Server4  
OscoreAsRsClient -name Server5  
OscoreAsRsClient -name Server6  

**Start up the CYPRESS DHT application (download separately)**  
./build_and_launch.sh 

**Next, start the first client. It will listen to commands from the DHT.**  
OscoreAsRsClient -dht -name Client1

**Then start the second client. It will listen to commands from the DHT.**  
OscoreAsRsClient -dht -name Client2

**Full list of command line parameters:**  
The following is the full list of command line parameters supported by the OscoreAsRsClient application:  
*Usage: [ -name Name ] [ -gm URI ] [ -as URI ] [ -delay Seconds ] [ -dht {URI} ] [ -help ]*
- *-name*: Name/Role of this peer
- *-gm*: Group Manager base URI
- *-as*: Authorization Server base URI
- *-delay*: - Delay in seconds before starting
- *-dht*: Use DHT: Optionally specify its WebSocket URI
- *-help*: - Print help

If the Group Manager or Authorization Server are running on a different host, the options *-gm* and *-as* can be used.  

In addition, the OscoreRsServer and OscoreAsServer applications also support the *-dht* parameter to enable logging to the DHT.  

Furthermore, the OscoreAsServer supports the *-db* parameter to indicate a connection string for the database.  
Example: "mysql://root:password@localhost:3306"  

**Relevant documentation**  
https://datatracker.ietf.org/doc/rfc8613/  
https://datatracker.ietf.org/doc/rfc9200/  
https://datatracker.ietf.org/doc/draft-ietf-core-oscore-groupcomm/  
https://datatracker.ietf.org/doc/draft-ietf-ace-key-groupcomm-oscore/

