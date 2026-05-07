package com.radware.interview;

import com.radware.interview.engine.Engine;
import com.radware.interview.models.Endpoint;
import com.radware.interview.models.Rule;
import com.radware.interview.strategy.StrategyExecutor;
import com.radware.interview.util.TestDataLoader;

import java.net.http.HttpRequest;
import java.util.ArrayList;
import java.util.List;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    static void main() {
        List<Rule> rules = new ArrayList<>();
        List<Endpoint> endpoints = new ArrayList<>();

        TestDataLoader.loadTestData(rules, endpoints);
        System.out.println(rules);
        System.out.println(endpoints);

        List<HttpRequest> allHttpRequests = new ArrayList<>();
        for (Rule rule : rules) {
            List<Endpoint> matchingEndpoints = Engine.matchingEndpointsForRule(rule, endpoints);
            List<Rule.Mutation> mutations = rule.getMutations();

            for(Endpoint endpoint : matchingEndpoints){
                for (Rule.Mutation mutation : mutations) {
                    List<HttpRequest> httpRequests = StrategyExecutor.executeStrategy(mutation.getStrategy(), endpoint, mutation.getTarget());
                    allHttpRequests.addAll(httpRequests);
                }// for all mutations
            }
        }// for all rules

        System.out.println(allHttpRequests);
    }// main
}