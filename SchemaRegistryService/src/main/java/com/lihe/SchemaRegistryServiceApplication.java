package com.lihe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.stream.schema.server.EnableSchemaRegistryServer;

@SpringBootApplication
@EnableDiscoveryClient
@EnableSchemaRegistryServer
public class SchemaRegistryServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SchemaRegistryServiceApplication.class, args);
	}
}
