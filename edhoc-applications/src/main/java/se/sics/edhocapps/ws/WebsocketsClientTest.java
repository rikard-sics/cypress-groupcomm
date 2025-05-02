package se.sics.edhocapps.ws;

import java.net.URI;

import javax.websocket.*;

// https://www.oracle.com/webfolder/technetwork/tutorials/obe/java/HomeWebsocket/WebsocketHome.html#section7
// https://www.piesocket.com/websocket-tester
// https://www.piesocket.com/blog/websocket
// https://socketsbay.com/test-websockets

// Old testing
public class WebsocketsClientTest {

	public static void main(String[] args) throws Exception {

		WebSocketContainer container = ContainerProvider.getWebSocketContainer();
		container.connectToServer(new Object(), new URI("wss://real.okcoin.cn:10440/websocket/okcoinapi"));
		
		System.out.println("HELLO");
	}

}
