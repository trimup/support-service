/*
 * Copyright (c) 2016. 51qed.com All Rights Reserved.
 */

package com.qed.filters;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;

/**
 * @author leo
 * @version V1.0.0
 * @package com.qed.filter
 * @date 16/7/15
 */
public class RestSignatureFilter extends OncePerRequestFilter {

    private static final String[] ignore_paths =
        new String[] {"/info", "/health", "swagger", "/api-docs", "/images", "/configuration",
            "favicon.ico", ".css", ".js"};


    @Value("${ignore_ips:127.0.0.1, 192.168., 120.55.120.173, 10.174.39.54, 121.41.106.210, 10.168.234.100}")
    private String[] ignore_ips = new String[] {"127.0.0.1", "192.168."};

    protected HttpServletRequest wrap(HttpServletRequest request) {
        return request;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        //API校验
        String signature = request.getHeader(SignatureHelper.SIGNATURE_HEADER);
        String apiKey = request.getHeader(SignatureHelper.APIKEY_HEADER);
        logger.debug("REST URL=>" + request.getRequestURL());
        final HttpServletRequest finalRequest = request;
        if (StringUtils.isEmpty(apiKey) || StringUtils.isEmpty(signature)) {
            if (Arrays.asList(ignore_ips).stream()//这些IP自动API签名
                .anyMatch(ip -> finalRequest.getRemoteAddr().contains(ip))) {
                request = wrap(request);
                signature = request.getHeader(SignatureHelper.SIGNATURE_HEADER);
                apiKey = request.getHeader(SignatureHelper.APIKEY_HEADER);
            }
        } else {
            if (Arrays.asList(ignore_paths).stream()//这些路径不做API_KEY校验
                .anyMatch(path -> finalRequest.getRequestURI().contains(path))) {
                logger.info("URL=>" + finalRequest.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }
        }
        String url = SignatureHelper.createSortedUrl(request);
        logger.info("SIGN URL=>" + url);
        try {
            if (!SignatureHelper.validateSignature(url, signature, apiKey)) {
                logger.warn("ValidateSignature=>" + url);
                logger.warn("Addr=>" + request.getRemoteAddr());
                Enumeration<String> headerNames = request.getHeaderNames();
                while (headerNames.hasMoreElements()) {
                    String nextElement = headerNames.nextElement();
                    logger.warn(nextElement + "=>" + request.getHeader(nextElement));
                }
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "rest signature failed validation.");
                return;
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "rest security server experienced an internal error.");
            return;
        }
        filterChain.doFilter(request, response);
    }

}
