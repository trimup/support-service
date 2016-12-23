/*
 * Copyright (c) 2016. lihe-fund All Rights Reserved.
 */

package com.lihe.filters;

import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * @author leo
 * @version V1.0.0
 * @package com.lihe.filter
 * @date 16/7/15
 */
@Component
public class ApiSignatureFilter extends RestSignatureFilter {


    protected HttpServletRequest wrap(HttpServletRequest request) {
        return new SignHttpRequestWrapper(request);
    }

}
