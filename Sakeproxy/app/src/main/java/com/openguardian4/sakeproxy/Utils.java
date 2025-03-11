package com.openguardian4.sakeproxy;

import android.util.Log;
import java.io.PrintWriter;
import java.io.StringWriter;

public class Utils {

    public static String getCallerClassName() {
        StackTraceElement[] stElements = Thread.currentThread().getStackTrace();
        for (int i=1; i<stElements.length; i++) {
            StackTraceElement ste = stElements[i];
            if (!ste.getClassName().equals(Utils.class.getName()) && ste.getClassName().indexOf("java.lang.Thread")!=0) {
                String[] name = ste.getClassName().split("\\.");
                return name[name.length - 1];
            }
        }
        return null;
    }

    public static String convertExceptionToString(Exception e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        String stackTrace = sw.toString();
        return stackTrace;
     //   Utils.logPrint("Error: " + stackTrace);
       // return sendHttpResponse(e.getMessage(), false);
    }


    public static void logPrint(String text) {
        String className = getCallerClassName();
        if (className != null) {
            Log.d(className, text);
        } else {
            Log.d("UNKNOWN", text);
        }
    }

    public static byte[] hexStrToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String bytesToHexStr(byte[] bytes) {
        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}
