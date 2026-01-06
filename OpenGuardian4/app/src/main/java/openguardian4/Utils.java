package openguardian4;

//import java.util.ArrayList;
//import java.util.List;

import openguardian4.Gatt.Converters.IMessageConverter;
//import openguardian4.Gatt.Converters.AbstractMessageConverter;
import openguardian4.Gatt.Message.GattMessageType;

public final class Utils {

	public static String bytesToHexStr(byte[] bytes) {
		StringBuilder hexStringBuilder = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			hexStringBuilder.append(String.format("%02X", bytes[i]));
			if (i < bytes.length - 1) {
				hexStringBuilder.append(" ");
			}
		}
		return hexStringBuilder.toString();
	}

	public static byte[] hexStrToBytes(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public static IMessageConverter getConverter(String service) {
		for (GattMessageType type : GattMessageType.values()) {
			if (type.supportedUuids.contains(service)) {
				return type.converter;
			}
		}
		return null;
	}

	/*
	public static List<String> removeComments(List<String> lines) {
        List<String> result = new ArrayList<>();
        
        for (String line : lines) {
            int commentIndex = line.indexOf('#');
            if (commentIndex != -1) {
                result.add(line.substring(0, commentIndex).trim());
            } else {
                result.add(line);
            }
        }
        
        return result;
    }
	*/

}