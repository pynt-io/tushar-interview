package com.radware.interview.engine;

import com.radware.interview.models.Endpoint;
import com.radware.interview.models.Rule;

import java.util.Collections;
import java.util.List;

public class Engine {

    public static List<Endpoint> matchingEndpointsForRule(Rule rule, List<Endpoint> endpoints) {

        if (rule == null || rule.getTarget() == null || endpoints == null) {
            return Collections.emptyList();
        }

        String targetPath = rule.getTarget().getPathPattern();

        List<String> targetMethods = rule.getTarget()
                .getMethods()
                .stream()
                .map(String::toUpperCase)
                .toList();

        return endpoints.stream()
                .filter(endpoint -> endpoint.getPath().equals(targetPath))
                .filter(endpoint ->
                        targetMethods.contains(endpoint.getMethod().toUpperCase())
                )
                .toList();
    }
}
