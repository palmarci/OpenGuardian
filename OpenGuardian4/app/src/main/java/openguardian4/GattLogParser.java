package openguardian4;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.regex.Pattern;

import openguardian4.Bluetooth.BtleDeviceType;
import openguardian4.Bluetooth.BtleMsg;
import openguardian4.Bluetooth.BtleMsgType;


public class GattLogParser {

    private static final Pattern HEADER_PATTERN = Pattern.compile(
            "^#.*?,\\d{4}-\\d{2}-\\d{2}_\\d{2}-\\d{2}-\\d{2},(encrypted|decrypted)$",
            Pattern.CASE_INSENSITIVE
    );

    public ArrayList<BtleMsg> parse(File file) throws Exception {

        ArrayList<BtleMsg> toret = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;

            // ---- Read header (must be first non-empty line)
            while ((line = br.readLine()) != null && line.trim().isEmpty()) {
                // skip empty lines
            }

            if (line == null) {
                throw new IllegalStateException("File is empty, header missing");
            }

            line = line.trim();

            if (!line.startsWith("#")) {
                throw new IllegalStateException("Header must be the first line");
            }

            if (!HEADER_PATTERN.matcher(line).matches()) {
                throw new IllegalArgumentException("Invalid header format: " + line);
            }

            boolean decryptedHeader = line.toLowerCase().endsWith("decrypted");
            if (!decryptedHeader) {
                throw new IllegalStateException("File is encrypted but decrypted data is required");
            }

            // ---- Parse data lines
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }

                String[] parts = line.split(",");
                if (parts.length < 6) {
                    System.err.println("WARNING: malformed data found on line: " + line);
                    continue; // ignore unrelated/malformed lines
                }

                int pktNo =  Integer.parseInt(parts[0]);
                BtleDeviceType from = BtleDeviceType.fromString(parts[1]);
                BtleDeviceType to = BtleDeviceType.fromString(parts[2]);
                BtleMsgType msgType = BtleMsgType.fromString(parts[3]);
                String service = parts[4].replace("-", "");
                if (service.length() != 32) {
                    throw new IllegalStateException("UUID size is not 32 for " + service + ". Perhaps you already resolved the uuids to human name?");
                }
                byte[] data = Utils.hexStrToBytes(parts[5]);

                var msg = new BtleMsg(pktNo, from, to, msgType, service, data);             
                toret.add(msg);
            }
        }

        System.err.println("Parsed " + toret.size() + " messages");
        return toret;
    }

}
