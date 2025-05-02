package se.sics.edhocapps.json.incoming;

// https://json2csharp.com/
// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
// {"Volatile":{"value":{"message":"hi","topic":"command_ed"}}}

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
