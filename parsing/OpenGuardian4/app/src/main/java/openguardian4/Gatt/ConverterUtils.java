package openguardian4.Gatt;

public final class ConverterUtils {
	private static final String UNPACKING_EXCEPTION_MESSAGE = "Not sufficient payload length for extracting";
	// private final InterfaceC7597a0 factory;

	// public AbstractConverter(InterfaceC7597a0 interfaceC7597a0) {
	// this.factory = interfaceC7597a0;
	// }

	/* renamed from: f */
	public static float unpackFloat(GattPayload Payload, int i, int i2) throws Exception {
		Float unpackFloat = Payload.unpackFloat(i, i2);
		if (unpackFloat != null) {
			return unpackFloat.floatValue();
		}
		throw new Exception(UNPACKING_EXCEPTION_MESSAGE);

		// throw new CrcException(String.format(UNPACKING_EXCEPTION_MESSAGE,
		// Integer.valueOf(i)), i2, Payload.m3851j());
	}

	/* renamed from: g */
	public static int unpackInt(GattPayload Payload, int i, int i2) throws Exception {
		Integer unpackInt = Payload.unpackInt(i, i2);
		if (unpackInt != null) {
			return unpackInt.intValue();
		}
		throw new Exception(UNPACKING_EXCEPTION_MESSAGE);

		// throw new CrcException(String.format(UNPACKING_EXCEPTION_MESSAGE,
		// Integer.valueOf(i)), i2, Payload.m3851j());
	}

	/* renamed from: h */
	public static long unpackLong(GattPayload Payload, int i, int i2) throws Exception {
		Long unpackLong = Payload.unpackLong(i, i2);
		if (unpackLong != null) {
			return unpackLong.longValue();
		}
		throw new Exception(UNPACKING_EXCEPTION_MESSAGE);
		// throw new CrcException(String.format(UNPACKING_EXCEPTION_MESSAGE,
		// Integer.valueOf(i)), i2, Payload.m3851j());
	}

	/* renamed from: i */
	public static String unpackString(GattPayload Payload, int i) throws Exception {
		String m3853h = Payload.m3854h(i);
		if (m3853h != null) {
			return m3853h;
		}
		throw new Exception(UNPACKING_EXCEPTION_MESSAGE);

		// throw new CrcException("Not sufficient payload length for extracting string",
		// i, Payload.m3851j());
	}

	/* renamed from: j */
	// public abstract Class<? extends T> getClass();
}