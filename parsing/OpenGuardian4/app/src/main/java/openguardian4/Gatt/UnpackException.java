package openguardian4.Gatt;

public class UnpackException extends Exception {
    private static final String defaultMsg = "Not sufficient payload length for extracting";

    public UnpackException() {
        super(defaultMsg);
    }
    public UnpackException(String message) {
        super(message);
    }
}
