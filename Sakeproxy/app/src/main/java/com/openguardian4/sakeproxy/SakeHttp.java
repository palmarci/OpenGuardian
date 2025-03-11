package com.openguardian4.sakeproxy;

import fi.iki.elonen.NanoHTTPD;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.medtronic.SakeClient.SakeClient;
import com.medtronic.SakeClient.SakeClientStatus;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

public class SakeHttp extends NanoHTTPD {

    private final Gson gson = new Gson();
    private SakeClient sakeClient;

    public SakeHttp(int port) {
        super(port);
        this.sakeClient = null;
    }

    // Utility method to build and send HTTP response with success or failure
    private NanoHTTPD.Response sendHttpResponse(Object data, boolean wasSuccess) {
        JsonObject httpResponseJson = new JsonObject();
        if (data instanceof byte[]) {
            data = Utils.bytesToHexStr((byte[]) data);
        }

        httpResponseJson.addProperty("success", wasSuccess);
        httpResponseJson.addProperty("data", data != null ? data.toString() : "");
        Utils.logPrint("sending http resp: success=" + wasSuccess + ", data=" + data);

        return newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(httpResponseJson));
    }

    @Override
    public Response serve(IHTTPSession session) {
        if (!Method.POST.equals(session.getMethod())) {
            return newFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, "text/plain", "Method Not Allowed");
        }

        try {
            Map<String, String> files = new HashMap<>();
            session.parseBody(files);
            String jsonStr = files.get("postData");
            JsonObject requestJson = gson.fromJson(jsonStr, JsonObject.class);
            String requestAction = requestJson.get("action").getAsString().trim();
            String requestDataStr = gson.fromJson(requestJson.get("data"), String.class);

            byte[] requestDataBytes = "null".equals(requestDataStr) ? null : Utils.hexStrToBytes(requestDataStr);

            Utils.logPrint("Received request: action=" + requestAction);

            // Handle request based on action
            switch (requestAction) {
                case "init":
                    return handleInit(requestDataBytes);

                case "get_error":
                    return handleGetError();

                case "close":
                    return handleClose();

                case "status":
                    return handleStatus();

                case "encrypt":
                    return handleEncrypt(requestDataBytes);

                case "decrypt":
                    return handleDecrypt(requestDataBytes);

                case "handshake":
                    return handleHandshake(requestDataBytes);

                default:
                    return sendHttpResponse("UNKNOWN_REQUEST", false);
            }
        } catch (IOException | ResponseException e) {
            e.printStackTrace();
            return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "text/plain", "Internal Server Error");
        }
    }

    // Handle the 'init' action: initializes the SakeClient
    private NanoHTTPD.Response handleInit(byte[] requestDataBytes) {
        try {
            this.sakeClient = new SakeClient();
            if (this.sakeClient.initKeyDb(requestDataBytes)) {
                return sendHttpResponse(null, true);
            } else {
                return sendHttpResponse("shit key db", false);
            }
        } catch (Exception e) {
            return handleError(e);
        }
    }

    // Handle the 'get_error' action: returns the last error from the client
    private NanoHTTPD.Response handleGetError() {
        String error = this.sakeClient != null ? this.sakeClient.getLastError() : "No client initialized";
        return sendHttpResponse(error, true);
    }

    // Handle the 'close' action: closes the SakeClient session
    private NanoHTTPD.Response handleClose() {
        this.sakeClient = null;
        return sendHttpResponse(null, true);
    }

    // Handle the 'status' action: retrieves the current client status
    private NanoHTTPD.Response handleStatus() {
        if (this.sakeClient == null) {
            return sendHttpResponse("LIBRARY_NOT_INITIALIZED", false);
        }

        SakeClientStatus status = this.sakeClient.getClientStatus();
        return sendHttpResponse(status != null ? status.toString() : "No status available", status != null);
    }

    // Handle the 'encrypt' action: performs encryption using the SakeClient
    private NanoHTTPD.Response handleEncrypt(byte[] requestDataBytes) {
        if (this.sakeClient == null) {
            return sendHttpResponse("LIBRARY_NOT_INITIALIZED", false);
        }

        byte[] responseData = this.sakeClient.encrypt(requestDataBytes);
        return sendHttpResponse(responseData, responseData != null);
    }

    // Handle the 'decrypt' action: performs decryption using the SakeClient
    private NanoHTTPD.Response handleDecrypt(byte[] requestDataBytes) {
        if (this.sakeClient == null) {
            return sendHttpResponse("LIBRARY_NOT_INITIALIZED", false);
        }

        byte[] responseData = this.sakeClient.decrypt(requestDataBytes);
        return sendHttpResponse(responseData, responseData != null);
    }

    // Handle the 'handshake' action: performs handshake with the SakeClient
    private NanoHTTPD.Response handleHandshake(byte[] requestDataBytes) {
        if (this.sakeClient == null) {
            return sendHttpResponse("LIBRARY_NOT_INITIALIZED", false);
        }

        try {
            byte[] responseData = this.sakeClient.doHandshake(requestDataBytes);
            return sendHttpResponse(responseData, true);
        } catch (Exception e) {
            return handleError(e);
        }
    }

    // Helper method to handle errors and log stack traces
    private NanoHTTPD.Response handleError(Exception e) {
        String err = Utils.convertExceptionToString(e);
        Utils.logPrint(err);
        return sendHttpResponse(err, false);
    }
}
