package openguardian4.Gatt.Message.Implementation.Socp;

public class SocpOperand<T> {
    private final T value;

    public SocpOperand(T t) {
        this.value = t;
    }

    /* renamed from: a */
    public T getValue() {
        return this.value;
    }

    public String toString() {
        return "SocpOperand{value=" + this.value + '}';
    }
}