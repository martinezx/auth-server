plugins {
	java
	id("org.springframework.boot") version "3.3.5"
	id("io.spring.dependency-management") version "1.1.6"
}

group = "org.xmdf"
version = "0.0.1-SNAPSHOT"

val profile = project.findProperty("spring.profiles.active")
println(profile)

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(17)
	}
}

configurations {
	compileOnly {
		extendsFrom(configurations.annotationProcessor.get())
	}
}

repositories {
	maven {
		url = uri("https://artifactory.home.xmdf.live/repository/maven-central/")
		credentials {
			username = property("artifactoyrUser") as String
			password = property("artifactoryPassword") as String
		}
	}
}

dependencies {
	compileOnly("org.projectlombok:lombok:1.18.34")
	annotationProcessor("org.projectlombok:lombok:1.18.34")

	developmentOnly("com.h2database:h2:2.3.232")

	implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.flywaydb:flyway-core:10.21.0")
	implementation("org.postgresql:postgresql:42.7.4")

	runtimeOnly("org.flywaydb:flyway-database-postgresql:10.21.0")

	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testImplementation("org.springframework.security:spring-security-test")

	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
