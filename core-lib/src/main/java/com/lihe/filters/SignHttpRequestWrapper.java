/*
 * Copyright (c) 2016. lihe-fund All Rights Reserved.
 */

package com.lihe.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.*;

/**
 * @author leo
 * @version V1.0.0
 * @package com.lihe.filter
 * @date 16/7/15
 */
public class SignHttpRequestWrapper extends HttpServletRequestWrapper {

    private static final Logger logger =
        LoggerFactory.getLogger(SignHttpRequestWrapper.class);
    // holds sign header and value mapping
    private final Map<String, String> signHeaders;

    public SignHttpRequestWrapper(HttpServletRequest request) {
        super(request);
        this.signHeaders = new HashMap<>();
        putHeader(SignatureHelper.APIKEY_HEADER, SignatureHelper.API_KEY);
        putHeader(SignatureHelper.TIMESTAMP_HEADER, "" + System.currentTimeMillis());
        try {
            putHeader(SignatureHelper.SIGNATURE_HEADER,
                SignatureHelper.createSignature(this, SignatureHelper.PRIVATE_KEY));
        } catch (Exception e) {
            logger.warn(e.getMessage(), e);
        }
    }

    private void putHeader(String name, String value) {
        this.signHeaders.put(name, value);
    }

    public HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        signHeaders.forEach((k, v) -> {
            headers.add(k, v);
        });
        return headers;
    }

    public String getHeader(String name) {
        // check the custom headers first
        String headerValue = signHeaders.get(name);

        if (headerValue != null) {
            return headerValue;
        }
        // else return from into the original wrapped object
        return ((HttpServletRequest) getRequest()).getHeader(name);
    }

    public Enumeration<String> getHeaderNames() {
        // create a set of the custom header names
        Set<String> set = new HashSet<>(signHeaders.keySet());

        // now add the headers from the wrapped request object
        @SuppressWarnings("unchecked")
        Enumeration<String> e = ((HttpServletRequest) getRequest()).getHeaderNames();
        while (e.hasMoreElements()) {
            // add the names of the request headers into the list
            String n = e.nextElement();
            set.add(n);
        }

        // create an enumeration from the set and return
        return Collections.enumeration(set);
    }
}
