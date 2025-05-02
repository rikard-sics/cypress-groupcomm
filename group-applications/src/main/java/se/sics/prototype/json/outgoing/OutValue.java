package se.sics.prototype.json.outgoing;

// https://json2csharp.com/
// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
// {"RequestPubMessage":{"value":{"message":"hi","topic":"output_dev1"}}}

public class OutValue {

	private String message;
	private String topic;

	public OutValue() {

	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getMessage() {
		return message;
	}

	public void setTopic(String topic) {
		this.topic = topic;
	}

	public String getTopic() {
		return topic;
	}
}
