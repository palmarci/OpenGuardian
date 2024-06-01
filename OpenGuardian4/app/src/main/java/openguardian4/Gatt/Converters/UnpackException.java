package openguardian4.Gatt.Converters;

public class UnpackException extends Exception {
    private static final String defaultMsg = "Unknown exception (maybe not sufficient payload length?) for extracting";

    public UnpackException() {
        super(defaultMsg);
    }
    public UnpackException(String message) {
        super(message);
    }
}


