package openguardian4.Bluetooth;

public enum BtleDeviceType {
    PUMP,
    APP,
    SENSOR;

    public static BtleDeviceType fromString(String value) {
    
        return BtleDeviceType.valueOf(value.trim().toUpperCase());
       
    }
}
