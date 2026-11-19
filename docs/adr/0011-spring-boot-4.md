# ADR 0011 - Spring Boot 4.1 instead of 3.x

- Status: Accepted (deviation from the spec, decided with the project owner on 2026-11-19)
- Addresses roadmap gap G9

## Context
The spec and roadmap assume Spring Boot 3. When Module 06 started, Spring Initializr offered only Boot 4.0.x and 4.1.x; the newest 3.x on Maven Central was 3.5.16. Starting a new security-sensitive service on a line that Initializr no longer offers risks missing future security fixes.

## Decision
Use **Spring Boot 4.1.2** (Spring Framework 7, Spring Security 7, Jackson 3) on **Java 21**, as recorded in `backend/pom.xml`. Everything else in the spec stays as written.

## Consequences
- Starter names follow Boot 4 modularization (for example `spring-boot-starter-webmvc`).
- Documentation and examples written for Boot 3 may need adjusting; the code is verified by the test suite rather than assumed.
- A later move to a newer 4.x release is a routine upgrade; a move back to 3.x is not planned.
