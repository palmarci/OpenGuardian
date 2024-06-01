package openguardian4.Gatt.Converters;

public class PackException extends Exception {
    private static final String defaultMsg = "Unknown exception while packing message to raw bytes";

    public PackException() {
        super(defaultMsg);
    }
    public PackException(String message) {
        super(message);
    }
}
