package openguardian4.Gatt.Message.Concrete;


import java.util.Objects;
import java.util.Set;

import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Enum.Concrete.ChangeSensorError;
import openguardian4.Gatt.Enum.Concrete.SensorError;
import openguardian4.Gatt.Enum.Concrete.AlgorithmDataFlags;


import openguardian4.Gatt.Enum.IntEnumConverter;

public class AlgorithmData extends AbstractGattMessage {
	public static final AlgorithmData EMPTY = new AlgorithmData(0, 0, 0);
	private final int changeSensorError;
	private final int flags;
	private final int sensorError;

	/* renamed from: e.g.f.a.d.d.a.n.w.a$a */
	/* loaded from: classes.dex */
	

	public AlgorithmData(int flags, int sensorError, int changeSensorError) {
		this.flags = flags;
		this.sensorError = sensorError;
		this.changeSensorError = changeSensorError;
	}

	public Set<ChangeSensorError> getChangeSensorErrors() {
		return IntEnumConverter.fromInt(this.changeSensorError, ChangeSensorError.values());
	}

	//this was not parsed int the original app 
	public Set<AlgorithmDataFlags> getFlags() {
		return IntEnumConverter.fromInt(this.flags, AlgorithmDataFlags.values());
	}

	/* renamed from: b */
	public Set<SensorError> getSensorErrors() {
		return IntEnumConverter.fromInt(this.sensorError, SensorError.values());
	}

	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		AlgorithmData algorithmData = (AlgorithmData) obj;
		return this.flags == algorithmData.flags && this.sensorError == algorithmData.sensorError
				&& this.changeSensorError == algorithmData.changeSensorError;
	}

	public int hashCode() {
		return Objects.hash(Integer.valueOf(this.flags), Integer.valueOf(this.sensorError),
				Integer.valueOf(this.changeSensorError));
	}

	public String toString() {
		return "AlgorithmData{flags=" + this.getFlags() + ", sensorError=" + this.getSensorErrors() + ", changeSensorError="
				+ this.getChangeSensorErrors() + '}';
	}
}
