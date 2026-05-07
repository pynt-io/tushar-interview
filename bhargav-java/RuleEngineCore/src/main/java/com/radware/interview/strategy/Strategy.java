package com.radware.interview.strategy;

import com.radware.interview.models.Endpoint;

import java.net.http.HttpRequest;
import java.util.List;

public interface Strategy {
    public List<HttpRequest> execute(Endpoint endpoint, String target);
    //TODO implement other strategies like BoundaryValuesStrategy and InvalidValuesStrategy
}

/*
Target<T> {

}*/
