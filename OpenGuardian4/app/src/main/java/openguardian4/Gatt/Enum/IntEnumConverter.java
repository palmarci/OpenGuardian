package openguardian4.Gatt.Enum;
import java.util.HashSet;
import java.util.Set;

import openguardian4.Gatt.Converters.UnpackException;

public final class IntEnumConverter {
    public static final int BITS_PER_BYTE = 8;
    public static final int BITS_PER_WORD = 16;

    /* renamed from: a */
    public static <F extends IGattEnum<Integer>> int toInt(Set<F> set) {
        int i = 0;
        for (F f : set) {
            i |= ((Integer) f.getValue()).intValue();
        }
        return i;
    }

    /* renamed from: b */
    public static <F extends IGattEnum<Integer>> Set<F> fromInt(int rawValue, F[] enumValues) {
        HashSet<F> hashSet = new HashSet<F>();
        for (F f : enumValues) {
            if ((((Integer) f.getValue()).intValue() & rawValue) != 0) {
                hashSet.add(f);
            }
        }
        return hashSet;
    }

    /* renamed from: c */
    public static <E extends IGattEnum<Integer>> E pickValuesHelper(int i, E[] eArr, E e) {
        //idk wtf this is
        for (E e2 : eArr) {
            if (i == ((Integer) e2.getValue()).intValue()) {
                return e2;
            }
        }
        return e;
    }

    public static <E extends IGattEnum<Integer>> E pickValues(int i2, E[] eArr) throws UnpackException {
        E e2 = (E) IntEnumConverter.pickValuesHelper(i2, eArr, null);
        if (e2 != null) {
            return e2;
        }
        throw new UnpackException("Failed to pick value '" + i2 + "' from " + eArr.getClass().getName());
    }
}