package openguardian.Gatt;

import java.util.HashMap;
import java.util.Map;

import openguardian.Gatt.Converters.*;

public final class ConverterMap {

	private static HashMap<String, IMessageConverter> setUpConverters() {
		HashMap<String, IMessageConverter> converterMap = new HashMap<String, IMessageConverter>();
		converterMap.put("5f0b2420-be34-11e4-bc62-0002a5d5c51b", new ConnectionActiveParamsConverter());
		return converterMap;
	}

	public static IMessageConverter getConverter(String uuid) {
		var converterMap = setUpConverters(); // TODO this is bad
		for (Map.Entry<String, IMessageConverter> map : converterMap.entrySet()) {
			if (uuid.equals(map.getKey())) {
				return map.getValue();
			}
		}
		return null;
	}

}
