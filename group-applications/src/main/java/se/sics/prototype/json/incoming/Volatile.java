package se.sics.prototype.json.incoming;

// https://json2csharp.com/
// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
// {"Volatile":{"value":{"message":"hi","topic":"command_dev1"}}}

public class Volatile {

	private InValue value;

	public InValue getValue() {
		return value;
	}

}
