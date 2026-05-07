package com.radware.interview.models;

import java.util.List;

public class Rule {

    private String rule;
    private String name;
    private String severity;
    private Target target;
    private List<Mutation> mutations;
    private List<Detection> detection;

    public String getRule() {
        return rule;
    }

    public void setRule(String rule) {
        this.rule = rule;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Target getTarget() {
        return target;
    }

    public void setTarget(Target target) {
        this.target = target;
    }

    public List<Mutation> getMutations() {
        return mutations;
    }

    public void setMutations(List<Mutation> mutations) {
        this.mutations = mutations;
    }

    public List<Detection> getDetection() {
        return detection;
    }

    public void setDetection(List<Detection> detection) {
        this.detection = detection;
    }

    public static class Target {
        private String pathPattern;
        private List<String> methods;

        public String getPathPattern() {
            return pathPattern;
        }

        public void setPathPattern(String pathPattern) {
            this.pathPattern = pathPattern;
        }

        public List<String> getMethods() {
            return methods;
        }

        public void setMethods(List<String> methods) {
            this.methods = methods;
        }
    }

    public static class Mutation {
        private String type;
        private String target;
        private String strategy;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getTarget() {
            return target;
        }

        public void setTarget(String target) {
            this.target = target;
        }

        public String getStrategy() {
            return strategy;
        }

        public void setStrategy(String strategy) {
            this.strategy = strategy;
        }
    }

    public static class Detection {
        private int statusCode;
        private String bodyContains;

        public int getStatusCode() {
            return statusCode;
        }

        public void setStatusCode(int statusCode) {
            this.statusCode = statusCode;
        }

        public String getBodyContains() {
            return bodyContains;
        }

        public void setBodyContains(String bodyContains) {
            this.bodyContains = bodyContains;
        }
    }
}