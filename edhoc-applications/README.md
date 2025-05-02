**Codebase for CYPRESS including applications using EDHOC and the optimized request solution.**

To setup and run the provided applications, follow the steps below. This will start 1 EDHOC client acting as initiator and 1 EDHOC server acting as responder. The applications support 4 different configuration alternatives (depending on which client and server is launched). Regardless of the option chosen, the client will execute EDHOC, and as its first OSCORE request sent trigger the server to turn on the light.

**Configurations**  
The 4 supported configurations are as follows:  
0. CoAP-only support.
1. Method 0. Optimized request: False.
2. Method 3. Optimized request: False.
3. Method 0. Optimized request: True.
4. Method 3. Optimized request: True.

**First start the EDHOC Server**  
PhaseXServer  

**Next start up the CYPRESS DHT application (download separately)**  
./build_and_launch.sh 

**Now start the EDHOC Client. It will listen to commands from the DHT.**  
PhaseXClient -dht  

**Full list of command line parameters:**  
The following is the full list of command line parameters supported by the PhaseXClient applications:  
*Usage: [ -server URI ] [ -dht {URI} ] [ -help ]*
- *-server*: EDHOC Server base URI
- *-dht*: Use DHT: Optionally specify its WebSocket URI
- *-help*: Print help

If the EDHOC Server is running on a different host than the EDHOC Client, the option *-server* can be used.

**Relevant documentation**  
https://datatracker.ietf.org/doc/rfc9528/  
https://datatracker.ietf.org/doc/rfc9668/  

