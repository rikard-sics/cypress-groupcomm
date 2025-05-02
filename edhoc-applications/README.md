**Codebase for CYPRESS including applications using EDHOC and the optimized request solution.**

To setup and run the provided applications, follow the steps below. This will start 1 EDHOC client acting as initiator and 1 EDHOC server acting as responder. The applications support 4 different configuration alternatives (depending on which client and server is launched). Regardless of the option chosen, the client will execute EDHOC, and as its first OSCORE request sent trigger the server to turn on the light. Follow-up requests are then handled by sending messages to the DHT via the provided Python script.

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

**Use the following interactive script to send commands to the DHT (and trigger the client)**  
python dht_rest_client.py

**Relevant documentation**  
https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/  
https://datatracker.ietf.org/doc/draft-ietf-core-oscore-edhoc/  

**DHT information**  
The EDHOC client applications listen for messages from the DHT on the following topic:  
* command_ed

And provide their output on the following topic  
* output_ed

Additionally, the CoAP client application listens for messages from the DHT on the following topic:  
* command_co

And provides its output on the following topic  
* output_co


The message structure is as follows:  
{"message": $payload, "topic": $topic }  
Valid payloads are "on" and "off", to turn on and off the lights respectively.  

