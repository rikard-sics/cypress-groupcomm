package se.sics.edhocapps.json.outgoing;

// https://json2csharp.com/
// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
// {"RequestPubMessage":{"value":{"message":"hi","topic":"output_ed"}}}

public class JsonOut {

	private RequestPubMessage RequestPubMessage;

	public JsonOut() {

	}

	public void setRequestPubMessage(RequestPubMessage requestPubMessage) {
		RequestPubMessage = requestPubMessage;
	}

	public RequestPubMessage getRequestPubMessage() {
		return RequestPubMessage;
	}

}
