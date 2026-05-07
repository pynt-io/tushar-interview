package com.radware.interview.strategy;

import com.radware.interview.models.Endpoint;

import java.net.http.HttpRequest;
import java.util.List;

public class IncrementDecrementStrategy implements Strategy{
    @Override
    public List<HttpRequest> execute(Endpoint endpoint, String target) {

        HttpRequest httpRequest = HttpRequest.newBuilder().build();
        // TODO : make two http requests for each of increment and decrement
        return List.of(httpRequest);
    }
}
