package com.radware.interview.strategy;

import com.radware.interview.models.Endpoint;

import java.net.http.HttpRequest;
import java.util.List;

public class StrategyExecutor {
    public static List<HttpRequest> executeStrategy(String strategyName, Endpoint endpoint, String target){
        switch (strategyName) {
            case "IncrementDecrementStrategy":
                return new IncrementDecrementStrategy().execute(endpoint, target);
            /*case "BoundaryValuesStrategy":
                return new BoundaryValuesStrategy().execute();
            case "InvalidValuesStrategy":
                return new InvalidValuesStrategy().execute();*/
            default:
                throw new IllegalArgumentException("Unknown strategy: " + strategyName);
        }
    }
}
