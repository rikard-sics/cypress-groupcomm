package se.sics.edhocapps.json.outgoing;

// https://json2csharp.com/
// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
// {"RequestPubMessage":{"value":{"message":"hi","topic":"output_ed"}}}

public class RequestPubMessage {

	private OutValue value;

	public RequestPubMessage() {

	}

	public void setValue(OutValue value) {
		this.value = value;
	}

	public OutValue getValue() {
		return value;
	}
}
