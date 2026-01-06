package openguardian4;

import openguardian4.Bluetooth.BtleMsg;
import java.io.File;

public class App {

	public static void main(String[] args) {
		if (args.length < 1) {
			System.err.println("No file was given in the arguments!");
			System.exit(1);
		}

		File inputFile = new File(args[0]);
		if(!inputFile.exists() || inputFile.isDirectory()) { 
			System.err.println("Given file does not exist!");
			System.exit(1);
		}

		try {
			var messages = new GattLogParser().parse(inputFile);

			int decode_count = 0;
			int skip_count = 0;

			for (BtleMsg msg : messages) {
				var decoded = msg.getDecodedMessage();
				if (decoded != null) {
					System.out.println(msg);
					decode_count++;
				} else {
					skip_count++;
				}
			}

			System.out.println("Decoded " + decode_count + ", skipped " + skip_count + " messages");

		} catch(Exception e) {
			System.err.println("Gatt log parsing exception: " + e);
		}

		return;
	
	}
}
