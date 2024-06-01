package openguardian4;

public enum RandomConstants {

    VIDEO_STREAM_MASK(240),
    MEASURED_SIZE_MASK(16777215);

    private final int value;

    RandomConstants(int i) {
        this.value = i;
    }

    public Integer getValue() {
        return Integer.valueOf(this.value);
    }

}