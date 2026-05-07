package com.radware.interview.models;

import java.util.Optional;

public class Endpoint {

    /**
     * e.g. "/users/{userId}"
     */
    private String path;

    /**
     * e.g. "GET"
     */
    private String method;

    private Optional<String> operationId = Optional.empty();

    public Endpoint() {
    }

    public Endpoint(String path, String method, Optional<String> operationId) {
        this.path = path;
        this.method = method;
        this.operationId = operationId;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public Optional<String> getOperationId() {
        return operationId;
    }

    public void setOperationId(Optional<String> operationId) {
        this.operationId = operationId;
    }
}