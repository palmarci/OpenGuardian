package openguardian4.Gatt.Message;

import java.util.Arrays;
import openguardian4.Utils;

import openguardian4.Gatt.Converters.UnpackException;
/* renamed from: e.g.g.a.a.e.b.e */
/* loaded from: classes.dex */
public class GattPayload  {

	private final byte[] value;

	/* renamed from: e.g.g.a.a.e.b.e$a */
	/* loaded from: classes.dex */

	public GattPayload() {
		this(new byte[0]);
	}

	public GattPayload(byte[] bArr) {
		this.value = bArr == null ? new byte[0] : bArr;
	}

	/* renamed from: b */
	public static float unpackFloatFrom2Bytes(byte b, byte b2) {
		return (float) (signExtend(byteToUInt8(b) + ((byteToUInt8(b2) & 15) << 8), 12)
				* Math.pow(10.0d, signExtend(byteToUInt8(b2) >> 4, 4)));
	}

	/* renamed from: c */
	public static float unpackFloatFrom4Bytes(byte b, byte b2, byte b3, byte b4) {
		return (float) (signExtend(byteToUInt8(b) + (byteToUInt8(b2) << 8) + (byteToUInt8(b3) << 16), 24)
				* Math.pow(10.0d, b4));
	}

	/* renamed from: e */
//	public static IllegalArgumentException FormatException(int format) {
//		return new IllegalArgumentException("Format type " + format + " is not supported");
//	}

	/* renamed from: i */
	public static int extractLowerNibble(int i) {
		return i & 15;
	}

	/* renamed from: l */
	public static int byteToUInt8(byte b) {
		return b & 255;
	}

	/* renamed from: m */
	public static int bytesToUInt16(byte b, byte b2) {
		return byteToUInt8(b) + (byteToUInt8(b2) << 8);
	}

	/* renamed from: n */
	public static int bytesToUInt24(byte b, byte b2, byte b3) {
		return byteToUInt8(b) + (byteToUInt8(b2) << 8) + (byteToUInt8(b3) << 16);
	}

	/* renamed from: o */
	public static int bytesToUnsignedInt32(byte b, byte b2, byte b3, byte b4) {
		return byteToUInt8(b) + (byteToUInt8(b2) << 8) + (byteToUInt8(b3) << 16) + (byteToUInt8(b4) << 24);
	}

	/* renamed from: p */
	public static int signExtend(int valueToExtend, int bitWidth) {
		int bitMask = 1 << (bitWidth - 1);
		return (valueToExtend & bitMask) != 0 ? (bitMask - (valueToExtend & (bitMask - 1))) * (-1) : valueToExtend;
	}

	/* renamed from: d */
	public Float unpackFloat(int format, int index) throws UnpackException  {
		float floatValue;

		int nibbleOffset = extractLowerNibble(format) + index;
		byte[] byteArray = this.value;

		if (nibbleOffset > byteArray.length) {
			return null;
		}

		if (format == PayloadFormat.FORMAT_SFLOAT.getValue()) {
			floatValue = unpackFloatFrom2Bytes(byteArray[index], byteArray[index + 1]);
		} else if (format == PayloadFormat.FORMAT_FLOAT.getValue()) {
			floatValue = unpackFloatFrom4Bytes(byteArray[index], byteArray[index + 1], byteArray[index + 2],
					byteArray[index + 3]);
		} else {
			throw new UnpackException("Invalid format: " + format);
		}

		return Float.valueOf(floatValue);
	}

	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		return Arrays.equals(this.value, ((GattPayload) obj).value);
	}

	/* renamed from: f */
	public Integer unpackInt(int format, int index) throws UnpackException  {
		int temp1;
		int temp2;
		int bitLength;
		int length = extractLowerNibble(format) + index;
		byte[] bArr = this.value;
		if (length > bArr.length) {
			return null;
		}
		if (format == PayloadFormat.FORMAT_SINT8.getValue()) {
			temp1 = byteToUInt8(bArr[index]);
			bitLength = 8;
		} else if (format == PayloadFormat.FORMAT_SINT16.getValue()) {
			temp1 = bytesToUInt16(bArr[index], bArr[index + 1]);
			bitLength = 16;
		} else if (format != PayloadFormat.FORMAT_SINT32.getValue()) {

			if (format == PayloadFormat.FORMAT_UINT8.getValue()) {
				temp2 = byteToUInt8(bArr[index]);
			} else if (format == PayloadFormat.FORMAT_UINT16.getValue()) {
				temp2 = bytesToUInt16(bArr[index], bArr[index + 1]);
			} else if (format == PayloadFormat.FORMAT_UINT24.getValue()) {
				temp2 = bytesToUInt24(bArr[index], bArr[index + 1], bArr[index + 2]);
			} else if (format == PayloadFormat.FORMAT_UINT32.getValue()) {
				temp2 = bytesToUnsignedInt32(bArr[index], bArr[index + 1], bArr[index + 2], bArr[index + 3]);
			} else {
				throw new UnpackException("Invalid format: " + format);
			}
			return Integer.valueOf(temp2);
		} else {
			temp1 = bytesToUnsignedInt32(bArr[index], bArr[index + 1], bArr[index + 2], bArr[index + 3]);
			bitLength = 32;
		}
		temp2 = signExtend(temp1, bitLength);
		return Integer.valueOf(temp2);
	}

	/* renamed from: g */
	public Long unpackLong(int i, int i2) throws UnpackException  {
		Integer unpackInt = unpackInt(i, i2);
		if (unpackInt != null) {
			return Long.valueOf(unpackInt.intValue() & 4294967295L);
		}
		return null;
	}

	/* renamed from: h */
	public String m3854h(int i) {
		byte[] bArr = this.value;
		if (bArr == null || i > bArr.length) {
			return null;
		}
		byte[] bArr2 = new byte[bArr.length - i];
		int i2 = 0;
		while (true) {
			byte[] bArr3 = this.value;
			if (i2 == bArr3.length - i) {
				return new String(bArr2);
			}
			bArr2[i2] = bArr3[i + i2];
			i2++;
		}
	}

	public int hashCode() {
		return Arrays.hashCode(this.value);
	}

	/* renamed from: j */
	public byte[] getCopy() {
		byte[] bArr = this.value;
		return Arrays.copyOf(bArr, bArr.length);
	}

	/* renamed from: k */
	public byte[] getCopyWithOffset(int offset, int length) {
		byte[] bArr = new byte[length];
		System.arraycopy(this.value, offset, bArr, 0, length);
		return bArr;
	}

	public String toString() {
		return "GattPayload{value=" + Utils.bytesToHexStr(this.value) + "}";
	}
}