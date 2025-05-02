package se.sics.prototype.json.incoming;

// https://json2csharp.com/
// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
// {"Volatile":{"value":{"message":"hi","topic":"command_dev1"}}}

public class InValue {

	private String message;
	private String topic;

	public String getTopic() {
		return topic;
	}

	public String getMessage() {
		return message;
	}

}
