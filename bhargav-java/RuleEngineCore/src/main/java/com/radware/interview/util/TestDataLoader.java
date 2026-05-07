package com.radware.interview.util;

import com.radware.interview.models.Endpoint;
import com.radware.interview.models.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class TestDataLoader {
    public static void loadTestData(List<Rule> rules, List<Endpoint> endpoints){
// --------------------
// Rule 1
// --------------------
        Rule rule1 = new Rule();
        rule1.setRule("BOLA-001");
        rule1.setName("Broken Object Level Authorization");
        rule1.setSeverity("high");

        Rule.Target target1 = new Rule.Target();
        target1.setPathPattern("/users/{userId}");
        target1.setMethods(List.of("GET", "PUT"));
        rule1.setTarget(target1);

        Rule.Mutation mutation1 = new Rule.Mutation();
        mutation1.setType("parameter_swap");
        mutation1.setTarget("path.userId");
        mutation1.setStrategy("increment");

        rule1.setMutations(List.of(mutation1));

        Rule.Detection detection1 = new Rule.Detection();
        detection1.setStatusCode(200);
        detection1.setBodyContains("email");

        rule1.setDetection(List.of(detection1));

        rules.add(rule1);

// --------------------
// Rule 2
// --------------------
        Rule rule2 = new Rule();
        rule2.setRule("BFLA-002");
        rule2.setName("Broken Function Level Authorization");
        rule2.setSeverity("critical");

        Rule.Target target2 = new Rule.Target();
        target2.setPathPattern("/admin/reports");
        target2.setMethods(List.of("POST"));
        rule2.setTarget(target2);

        Rule.Mutation mutation2 = new Rule.Mutation();
        mutation2.setType("role_escalation");
        mutation2.setTarget("header.Authorization");
        mutation2.setStrategy("replace_token");

        rule2.setMutations(List.of(mutation2));

        Rule.Detection detection2 = new Rule.Detection();
        detection2.setStatusCode(200);
        detection2.setBodyContains("reportId");

        rule2.setDetection(List.of(detection2));

        rules.add(rule2);

// --------------------
// Endpoints
// --------------------
        Endpoint endpoint1 = new Endpoint(
                "/users/{userId}",
                "GET",
                Optional.of("getUserById")
        );

        Endpoint endpoint2 = new Endpoint(
                "/users/{userId}",
                "PUT",
                Optional.of("updateUser")
        );

        Endpoint endpoint3 = new Endpoint(
                "/admin/reports",
                "POST",
                Optional.of("createReport")
        );

        Endpoint endpoint4 = new Endpoint(
                "/products",
                "GET",
                Optional.empty()
        );

        endpoints.add(endpoint1);
        endpoints.add(endpoint2);
        endpoints.add(endpoint3);
        endpoints.add(endpoint4);
    }
}
