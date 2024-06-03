package com.openguardian4.sakeproxy;

import fi.iki.elonen.NanoHTTPD;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import com.medtronic.SakeClient.SakeClient;
import com.medtronic.SakeClient.SakeClientStatus;

import java.util.*;
import java.io.IOException;
import java.lang.reflect.Method;

public class SakeHttp extends NanoHTTPD {

    private final Gson gson = new Gson();
    private SakeClient sakeClient;

    public SakeHttp(int port) {
        super(port);
        this.sakeClient = null;
        // sakeClient = new SakeClient(new byte[0]); // Initialize with a default value
    }

    private NanoHTTPD.Response sendHttpResponse(Object data, boolean wasSuccess) {
        JsonObject httpResponseJson = new JsonObject();
        if (data instanceof byte[]) {
            data = Utils.bytesToHexStr((byte[]) data);
        }

        if (data == null) {
            data = "";
        }

        httpResponseJson.addProperty("success", wasSuccess);
        httpResponseJson.addProperty("data", (String) data);
        Utils.logPrint("sending http resp: success=" + wasSuccess + ", data=" + (String) data);
        return newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(httpResponseJson));
    }

    @Override
    public Response serve(IHTTPSession session) {
        if (Method.POST.equals(session.getMethod())) {
            try {
                Map<String, String> files = new HashMap<>();
                session.parseBody(files);
                String jsonStr = files.get("postData");

                JsonObject requestJson = gson.fromJson(jsonStr, JsonObject.class);
                String requestAction = requestJson.get("action").getAsString();
                requestAction = requestAction.trim();
                String requestDataStr = gson.fromJson(requestJson.get("data"), String.class);
                byte[] requestDataBytes = null;
                if (!requestDataStr.equals("null")) {
                    requestDataBytes = Utils.hexStrToBytes(requestDataStr);
                }

                byte[] sakeResponseData = null;

                Utils.logPrint("got request: " + requestAction);

                // check if we are initialized or not - allow only init requests
                if (this.sakeClient == null) {

                    if (requestAction.equals("init")) {
                        Utils.logPrint("trying to start sakeclient...");
                       // boolean success = false;
                        try {
                            this.sakeClient = new SakeClient(requestDataBytes);
                            return sendHttpResponse(null, true);
                        } catch (Exception e) {
                            Utils.logPrint("failed to open key db!");
                            this.sakeClient = null;
                            return sendHttpResponse(e.getMessage(), false);

                        }
                    }

                    return sendHttpResponse("LIBRARY_NOT_INITIALIZED", false);
                }

                // handle restart of library - TODO: session shit
                if (requestAction.equals("close")) {
                    this.sakeClient = null;
                    return sendHttpResponse(null, true);
                }

                // special status request
                if (requestAction.equals("status")) {
                    SakeClientStatus status = this.sakeClient.getClientStatus();
                    return sendHttpResponse(status.toString(), status != null);
                }

                if ("encrypt".equals(requestAction)) {
                    sakeResponseData = this.sakeClient.encrypt(requestDataBytes);
                    return sendHttpResponse(sakeResponseData, sakeResponseData != null);
                } else if ("decrypt".equals(requestAction)) {
                    sakeResponseData = this.sakeClient.decrypt(requestDataBytes);
                    return sendHttpResponse(sakeResponseData, sakeResponseData != null);
                } else if ("handshake".equals(requestAction)) {
                    // bool success = false;
                    // byte[] resp = null;
                    try {
                        sakeResponseData = this.sakeClient.doHandshake(requestDataBytes);
                        return sendHttpResponse(sakeResponseData, true); // may return null actually
                    } catch (Exception e) {
                        return sendHttpResponse(e.getMessage(), false); // may return null actually
                    }
                }

                return sendHttpResponse("UNKNOWN_REQUEST", false);

            } catch (IOException | ResponseException e) {
                e.printStackTrace();
                return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "text/plain",
                        "Internal Server Error");
            }
        } else {
            return newFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, "text/plain", "Method Not Allowed");
        }
    }
}