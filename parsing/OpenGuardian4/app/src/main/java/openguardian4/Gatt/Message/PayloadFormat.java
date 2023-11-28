package openguardian4.Gatt.Message;

public enum PayloadFormat {
    
    FORMAT_FLOAT(52),
    FORMAT_SFLOAT(50),
    FORMAT_SINT16(34),
    FORMAT_SINT32(36),
    FORMAT_SINT8(33),
    FORMAT_UINT16(18),
    FORMAT_UINT24(19),
    FORMAT_UINT32(20),
    FORMAT_UINT8(17);

    private Integer value;


    PayloadFormat(Integer value) {
        this.value = value;
    }

    public Integer getValue() {
        return this.value;
    }


}
