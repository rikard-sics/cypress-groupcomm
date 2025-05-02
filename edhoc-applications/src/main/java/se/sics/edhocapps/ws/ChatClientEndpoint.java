package se.sics.edhocapps.ws;
// package se.sics.prototype.ws;
//
// import java.io.BufferedReader;
// import java.io.IOException;
// import java.io.InputStreamReader;
// import java.net.URI;
// import java.net.URISyntaxException;
// import java.util.concurrent.CountDownLatch;
// import jakarta.websocket.ClientEndpoint;
// import jakarta.websocket.CloseReason;
// import jakarta.websocket.DeploymentException;
// import jakarta.websocket.OnClose;
// import jakarta.websocket.OnMessage;
// import jakarta.websocket.OnOpen;
// import jakarta.websocket.Session;
// import org.glassfish.tyrus.client.ClientManager;
//
//// https://raw.githubusercontent.com/javiergs/Medium/main/Websockets/ChatClientEndpoint.java
//// https://socketsbay.com/test-websockets
//
// @ClientEndpoint
// public class ChatClientEndpoint {
//
// private static CountDownLatch latch;
//
// @OnOpen
// public void onOpen(Session session) {
// System.out.println("--- Connected " + session.getId());
// // try {
// // session.getBasicRemote().sendText("start");
// // } catch (IOException e) {
// // throw new RuntimeException(e);
// // }
// }
//
// @OnMessage
// public String onMessage(String message, Session session) {
// BufferedReader bufferRead = new BufferedReader(new
// InputStreamReader(System.in));
// // try {
// System.out.println("--- Received " + message);
//
// // Device 1 filter
// if
// (message.equals("{\"Volatile\":{\"value\":{\"message\":\"hi\",\"topic\":\"command_ed\"}}}"))
// {
// System.out.println("Filter matched message (EDHOC client)!");
//
// // Send group requests etc. save answers as string
// try {
// Thread.sleep(5000);
// } catch (InterruptedException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// }
//
// // return null;
// return
// ("{\"RequestPubMessage\":{\"value\":{\"message\":\"hi\",\"topic\":\"output_ed\"}}}");
// }
//
// // Device 2 filter
// else if
// (message.equals("{\"Volatile\":{\"value\":{\"message\":\"hi\",\"topic\":\"command_dev2\"}}}"))
// {
// System.out.println("Filter matched message (device 2)!");
//
// // Send group requests etc. save answers as string
// try {
// Thread.sleep(5000);
// } catch (InterruptedException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// }
//
// return
// ("{\"RequestPubMessage\":{\"value\":{\"message\":\"hi\",\"topic\":\"output_dev2\"}}}");
// }
//
// // String userInput = bufferRead.readLine();
// // return userInput;
// return null; // Sent as response to DHT
// // } catch (IOException e) {
// // throw new RuntimeException(e);
// // }
// }
//
// @OnClose
// public void onClose(Session session, CloseReason closeReason) {
// System.out.println("Session " + session.getId() + " closed because " +
// closeReason);
// latch.countDown();
// }
//
// public static void main(String[] args) throws DeploymentException,
// IOException {
// latch = new CountDownLatch(1000);
// ClientManager client = ClientManager.createClient();
// try {
// // wss://socketsbay.com/wss/v2/2/demo/
// URI uri = new URI("ws://localhost:3000/ws");
// client.connectToServer(ChatClientEndpoint.class, uri);
// latch.await();
// } catch (DeploymentException | URISyntaxException | InterruptedException e) {
// e.printStackTrace();
// }
// }
// }
