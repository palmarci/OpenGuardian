package openguardian.Gatt;

import java.util.Arrays;

/* renamed from: e.g.g.a.a.e.b.e */
/* loaded from: classes.dex */
public class GattPayload {
	public static final int FORMAT_FLOAT = 52;
	public static final int FORMAT_SFLOAT = 50;
	public static final int FORMAT_SINT16 = 34;
	public static final int FORMAT_SINT32 = 36;
	public static final int FORMAT_SINT8 = 33;
	public static final int FORMAT_UINT16 = 18;
	public static final int FORMAT_UINT24 = 19;
	public static final int FORMAT_UINT32 = 20;
	public static final int FORMAT_UINT8 = 17;
	private final byte[] value;

	/* renamed from: e.g.g.a.a.e.b.e$a */
	/* loaded from: classes.dex */
	public static class C7802a {
		private byte[] tempValue;

		/* renamed from: c */
		public static int m3843c(int i, int i2) {
			if (i < 0) {
				int i3 = 1 << (i2 - 1);
				return (i & (i3 - 1)) + i3;
			}
			return i;
		}

		/* renamed from: a */
		public GattPayload m3845a() {
			byte[] bArr = this.tempValue;
			return new GattPayload(Arrays.copyOf(bArr, bArr.length));
		}

		/* renamed from: b */
		public final void m3844b(int i) {
			byte[] bArr = this.tempValue;
			if (bArr != null) {
				byte[] bArr2 = new byte[i];
				this.tempValue = bArr2;
				System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
			}
		}

		/* renamed from: d */
		public C7802a m3842d(int i, int i2, int i3) {
			int And15 = GattPayload.And15(i2) + i3;
			if (this.tempValue == null) {
				this.tempValue = new byte[And15];
			}
			if (And15 > this.tempValue.length) {
				m3844b(And15);
			}
			if (i2 != 17) {
				if (i2 != 18) {
					if (i2 != 20) {
						if (i2 == 36) {
							i = m3843c(i, 32);
						} else if (i2 == 33) {
							i = m3843c(i, 8);
						} else if (i2 != 34) {
							throw GattPayload.FormatException(i2);
						} else {
							i = m3843c(i, 16);
						}
					}
					byte[] bArr = this.tempValue;
					int i4 = i3 + 1;
					bArr[i3] = (byte) (i & 255);
					int i5 = i4 + 1;
					bArr[i4] = (byte) ((i >> 8) & 255);
					bArr[i5] = (byte) ((i >> 16) & 255);
					bArr[i5 + 1] = (byte) ((i >> 24) & 255);
					return this;
				}
				byte[] bArr2 = this.tempValue;
				bArr2[i3] = (byte) (i & 255);
				bArr2[i3 + 1] = (byte) ((i >> 8) & 255);
				return this;
			}
			this.tempValue[i3] = (byte) (i & 255);
			return this;
		}

		/* renamed from: e */
		public C7802a m3841e(long j, int i, int i2) {
			m3842d((int) (j & 4294967295L), i, i2);
			return this;
		}

		/* renamed from: f */
		public C7802a m3840f(String str) {
			this.tempValue = str.getBytes();
			return this;
		}

		/* renamed from: g */
		public C7802a m3839g(byte[] bArr) {
			this.tempValue = bArr != null ? (byte[]) bArr.clone() : null;
			return this;
		}

		/* renamed from: h */
		public C7802a m3838h(byte[] bArr, int i) {
			int length = bArr.length + i;
			if (this.tempValue == null) {
				this.tempValue = new byte[length];
			}
			if (this.tempValue.length < length) {
				m3844b(length);
			}
			System.arraycopy(bArr, 0, this.tempValue, i, bArr.length);
			return this;
		}
	}

	public GattPayload() {
		this(new byte[0]);
	}

	public GattPayload(byte[] bArr) {
		this.value = bArr == null ? new byte[0] : bArr;
	}

	/* renamed from: b */
	public static float m3860b(byte b, byte b2) {
		return (float) (signExtend(And255(b) + ((And255(b2) & 15) << 8), 12)
				* Math.pow(10.0d, signExtend(And255(b2) >> 4, 4)));
	}

	/* renamed from: c */
	public static float m3859c(byte b, byte b2, byte b3, byte b4) {
		return (float) (signExtend(And255(b) + (And255(b2) << 8) + (And255(b3) << 16), 24) * Math.pow(10.0d, b4));
	}

	/* renamed from: e */
	public static IllegalArgumentException FormatException(int i) {
		return new IllegalArgumentException("Format type " + i + " is not supported");
	}

	/* renamed from: i */
	public static int And15(int i) {
		return i & 15;
	}

	/* renamed from: l */
	public static int And255(byte b) {
		return b & 255;
	}

	/* renamed from: m */
	public static int bytesToUInt16(byte b, byte b2) {
		return And255(b) + (And255(b2) << 8);
	}

	/* renamed from: n */
	public static int bytesToUInt24(byte b, byte b2, byte b3) {
		return And255(b) + (And255(b2) << 8) + (And255(b3) << 16);
	}

	/* renamed from: o */
	public static int bytesToUnsignedInt32(byte b, byte b2, byte b3, byte b4) {
		return And255(b) + (And255(b2) << 8) + (And255(b3) << 16) + (And255(b4) << 24);
	}

	/* renamed from: p */
	public static int signExtend(int i, int i2) {
		int i3 = 1 << (i2 - 1);
		return (i & i3) != 0 ? (i3 - (i & (i3 - 1))) * (-1) : i;
	}

	/* renamed from: d */
	public Float unpackFloat(int i, int i2) {
		float m3860b;
		int And15 = And15(i) + i2;
		byte[] bArr = this.value;
		if (And15 > bArr.length) {
			return null;
		}
		if (i == 50) {
			m3860b = m3860b(bArr[i2], bArr[i2 + 1]);
		} else if (i != 52) {
			throw FormatException(i);
		} else {
			m3860b = m3859c(bArr[i2], bArr[i2 + 1], bArr[i2 + 2], bArr[i2 + 3]);
		}
		return Float.valueOf(m3860b);
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
	public Integer unpackInt(int i, int i2) {
		int And255;
		int i3;
		int temp;
		int And15 = And15(i) + i2;
		byte[] bArr = this.value;
		if (And15 > bArr.length) {
			return null;
		}
		if (i == 33) {
			And255 = And255(bArr[i2]);
			i3 = 8;
		} else if (i == 34) {
			And255 = bytesToUInt16(bArr[i2], bArr[i2 + 1]);
			i3 = 16;
		} else if (i != 36) {
			switch (i) {
				case 17:
					temp = And255(bArr[i2]);
					break;
				case 18:
					temp = bytesToUInt16(bArr[i2], bArr[i2 + 1]);
					break;
				case 19:
					temp = bytesToUInt24(bArr[i2], bArr[i2 + 1], bArr[i2 + 2]);
					break;
				case 20:
					temp = bytesToUnsignedInt32(bArr[i2], bArr[i2 + 1], bArr[i2 + 2], bArr[i2 + 3]);
					break;
				default:
					throw FormatException(i);
			}
			return Integer.valueOf(temp);
		} else {
			And255 = bytesToUnsignedInt32(bArr[i2], bArr[i2 + 1], bArr[i2 + 2], bArr[i2 + 3]);
			i3 = 32;
		}
		temp = signExtend(And255, i3);
		return Integer.valueOf(temp);
	}

	/* renamed from: g */
	public Long unpackLong(int i, int i2) {
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
	public byte[] getByteArrayCopy() {
		byte[] bArr = this.value;
		return Arrays.copyOf(bArr, bArr.length);
	}

	/* renamed from: k */
	public byte[] getArrayCopy(int i, int i2) {
		byte[] bArr = new byte[i2];
		System.arraycopy(this.value, i, bArr, 0, i2);
		return bArr;
	}


	public String toString() {
		return "GattPayload{value=" + Arrays.toString(this.value) + "}";
	}
}