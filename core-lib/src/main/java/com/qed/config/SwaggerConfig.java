/*
 * Copyright (c) 2016. 51qed.com All Rights Reserved.
 */

package com.qed.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.CollectionUtils;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static com.google.common.base.Predicates.or;
import static springfox.documentation.builders.PathSelectors.regex;

/**
 * @author leo
 * @version V1.0.0
 * @package com.qed
 * @date 16/7/14
 */
@Configuration
@EnableSwagger2
public class SwaggerConfig {

    @Value("${spring.application.name}")
    private String name;

    @Value("${EXPORT_PATHS:}")
    private String[] pathArray = {"/"};

    @Bean
    public Docket api() {
        List<String> paths = Arrays.asList(pathArray);
        return new Docket(DocumentationType.SWAGGER_2)
            .groupName(name)
            .apiInfo(apiInfo())
            .securitySchemes(Collections.singletonList(apiKey()))
            .securityContexts(Collections.singletonList(securityContext()))
            .select()
            .paths(!CollectionUtils.isEmpty(paths) ?
                or(paths.stream().map(p -> regex(p)).collect(Collectors.toList())) :
                PathSelectors.any())
            .build();
    }


    private ApiKey apiKey() {
        return new ApiKey("ApiKey", "api_key", "header");
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder()
            .securityReferences(defaultAuth())
            .build();
    }

    List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope
            = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return Collections.singletonList(new SecurityReference("ApiKey", authorizationScopes));
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
            .title(name)
            //            .description(name)
            .contact("企额贷")
            .license("51qed.com All Rights Reserved")
            .version("1.0")
            .build();
    }
}
