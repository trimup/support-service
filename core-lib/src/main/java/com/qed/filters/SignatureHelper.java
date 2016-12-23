/*
 * Copyright (c) 2016. 51qed.com All Rights Reserved.
 */

package com.qed.filters;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * @author leo
 * @version V1.0.0
 * @package com.qed.filter
 * @date 16/7/15
 */
public final class SignatureHelper {
    private static final Logger logger =
        LoggerFactory.getLogger(SignatureHelper.class);
    public static final String API_KEY = "com.51qed.api";
    public static final String PUBLIC_KEY =
        "MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1_U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq_xfW6MPbLm1Vs14E7gB00b_JmYLdrmVClpJ-f6AR7ECLCT7up1_63xhv4O1fnxqimFQ8E-4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC_BYHPUCgYEA9-GghdabPd7LvKtcNrhXuXmUr7v6OuqC-VdMCz0HgmdRWVeOutRZT-ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN_C_ohNWLx-2J6ASQ7zKTxvqhRkImog9_hWuWfBpKLZl6Ae1UlZAFMO_7PSSoDgYQAAoGAOF7wZCHXFC72bO-gR3FR5HG7FUzwolZcL5ak58vC6siCCWke6rvpcyvj2X_d2HNGBI4al8WgtjMnkfD88Z6togoym8nR2Ua985_35ey0t5G2jVgfPt0R1tO_Xn0ieCTxuC2WCIrtkbpzbqfMY1bHqQhoVcOmlfF9S8F-lvRlJ9w";
    public static final String PRIVATE_KEY =
        "MIIBTAIBADCCASwGByqGSM44BAEwggEfAoGBAP1_U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq_xfW6MPbLm1Vs14E7gB00b_JmYLdrmVClpJ-f6AR7ECLCT7up1_63xhv4O1fnxqimFQ8E-4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC_BYHPUCgYEA9-GghdabPd7LvKtcNrhXuXmUr7v6OuqC-VdMCz0HgmdRWVeOutRZT-ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN_C_ohNWLx-2J6ASQ7zKTxvqhRkImog9_hWuWfBpKLZl6Ae1UlZAFMO_7PSSoEFwIVAIjffZtYDHTD2T2qf_cH6fHAS6HQ";
    public static final String APIKEY_HEADER = "api_key";
    public static final String TIMESTAMP_HEADER = "timestamp";
    public static final String SIGNATURE_HEADER = "signature";
    public static final List<String> SIGNATURE_KEYWORDS =
        Arrays.asList(APIKEY_HEADER, TIMESTAMP_HEADER);

    private static final String ALGORITHM = "DSA";

    public static String getPublicKey(String apiKey) {
        if (apiKey.equals(SignatureHelper.API_KEY)) {
            return SignatureHelper.PUBLIC_KEY;
        }
        return null;
    }

    public static String createSignature(HttpServletRequest request, String privateKey)
        throws Exception {

        //        TreeMap<String, String> sortedHeaders = new TreeMap<>();
        //        for (String key : headers.keySet()) {
        //            if (SIGNATURE_KEYWORDS.contains(key)) {
        //                sortedHeaders.put(key, headers.get(key).get(0));
        //            }
        //        }
        String sortedUrl = createSortedUrl(request);
        logger.warn("CreateSignature URL=>" + sortedUrl);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        byte[] privateKeyBytes = Base64.decodeBase64(privateKey.getBytes());
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        Signature sig = Signature.getInstance(ALGORITHM);
        sig.initSign(keyFactory.generatePrivate(privateKeySpec));
        sig.update(sortedUrl.getBytes());

        return Base64.encodeBase64URLSafeString(sig.sign());
    }

    private static PublicKey decodePublicKey(String publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        byte[] publicKeyBytes = Base64.decodeBase64(publicKey);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static boolean validateSignature(String url, String signatureString, String apiKey)
        throws InvalidKeyException, Exception {
        if (apiKey == null)
            return false;
        String publicKey = SignatureHelper.getPublicKey(apiKey);
        if (publicKey == null)
            return false;
        if (signatureString == null)
            return false;
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initVerify(decodePublicKey(publicKey));
        signature.update(url.getBytes());
        try {
            return signature.verify(Base64.decodeBase64(signatureString));
        } catch (SignatureException e) {
            return false;
        }
    }

    public static String createSortedUrl(HttpServletRequest request) {

        // use a TreeMap to sort the headers and parameters
        TreeMap<String, String> headersAndParams = new TreeMap<>();

        // load header values we care about
        Enumeration e = request.getHeaderNames();
        while (e.hasMoreElements()) {
            String key = (String) e.nextElement();
            if (SIGNATURE_KEYWORDS.contains(key)) {
                headersAndParams.put(key, request.getHeader(key));
            }
        }
        //load parameters
        Map parameterMap = request.getParameterMap();
        for (Object key : parameterMap.keySet()) {
            String[] o = (String[]) parameterMap.get(key);
            if (o == null || o.length == 0)
                continue;
            headersAndParams.put((String) key, o[0]);
        }

        return createSortedUrl(
            request.getContextPath() + request.getServletPath() + (StringUtils
                .isEmpty(request.getPathInfo()) ? "" : request.getPathInfo()),
            headersAndParams);

    }

    public static String createSortedUrl(String url, TreeMap<String, String> headersAndParams) {
        // build the url with headers and parms sorted
        String params = "";
        for (String key : headersAndParams.keySet()) {
            if (params.length() > 0) {
                params += "&";
            }
            params += key + "=" + headersAndParams.get(key).toString();
        }
        if (!url.endsWith("?"))
            url += "?";
        return url + params;
    }

    public static void main(String[] args) throws Exception {

        // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(1024);
        KeyPair keypair = keyGen.genKeyPair();
        PrivateKey privateKey = keypair.getPrivate();
        PublicKey publicKey = keypair.getPublic();

        // Get the bytes of the public and private keys (these go in the database with API Key)
        byte[] privateKeyEncoded = privateKey.getEncoded();
        byte[] publicKeyEncoded = publicKey.getEncoded();

        System.out.println("Private Key: " + Base64.encodeBase64URLSafeString(privateKeyEncoded));
        System.out.println("Public Key: " + Base64.encodeBase64URLSafeString(publicKeyEncoded));

    }
}
