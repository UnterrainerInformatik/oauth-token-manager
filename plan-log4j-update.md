# Log4j Migration Plan: oauth-token-manager

**Layer**: 6 — update after `http-server`.

## Before Starting

Prompt the user for the following version numbers before making any changes:

| Variable | Question |
|----------|----------|
| `NEW_PARENT_POM_VERSION` | What is the new `parent-pom` version? |
| `NEW_HTTP_SERVER_VERSION` | What is the new `http-server` version? |
| `OWN_NEW_VERSION` | What version should `oauth-token-manager` be bumped to? (currently `1.0.11`) |

## Context

Part of a migration from Log4j 1.x to Log4j 2.25.3 across all libraries. Has 2 classes using `@Slf4j` — no code changes needed (SLF4J API is unchanged).

> **IMPORTANT for execution**: This plan should be executed by actually making the file changes described below — create the new `log4j2.xml` / `log4j2-test.xml` files with the content provided, and delete the old `log4j.properties` files. Do not leave the config migration as a manual step.

## Current State

- **Artifact**: `info.unterrainer.commons:oauth-token-manager`
- **Parent**: `parent-pom:1.0.2`
- **In-house dependencies**:
  - `http-server:1.0.0` — bump to new version
- **log4j.properties**: YES (main + test, identical content)
- **@Slf4j usage**: 2 classes

### Current `log4j.properties` content (both main and test):
```properties
log4j.rootLogger=DEBUG, A1
log4j.appender.A1=org.apache.log4j.ConsoleAppender
log4j.appender.A1.layout=org.apache.log4j.PatternLayout
log4j.appender.A1.layout.charset=UTF-8
log4j.appender.A1.layout.ConversionPattern=%-4r [%t] %-5p %c %x - %m%n
log4j.logger.io.netty=WARN
log4j.logger.org.eclipse.milo=WARN
```

## Steps

### 1. Update parent version in `pom.xml`

Change the parent version (line 8) to the new parent-pom version:

```xml
<parent>
    <groupId>info.unterrainer.commons</groupId>
    <artifactId>parent-pom</artifactId>
    <version>NEW_PARENT_POM_VERSION</version>
</parent>
```

### 2. Update in-house dependency versions in `pom.xml`

```xml
<dependency>
    <groupId>info.unterrainer.commons</groupId>
    <artifactId>http-server</artifactId>
    <version>NEW_HTTP_SERVER_VERSION</version>
</dependency>
```

### 3. Bump own version

Increment `<version>` (line 13, currently `1.0.11`).

### 4. Migrate logging config: create `src/main/resources/log4j2.xml`

Replace the old `log4j.properties` with this Log4j 2 XML config:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout charset="UTF-8"
                           pattern="%-4r [%t] %-5p %c %x - %m%n"/>
        </Console>
    </Appenders>
    <Loggers>
        <Logger name="io.netty" level="WARN"/>
        <Logger name="org.eclipse.milo" level="WARN"/>
        <Root level="DEBUG">
            <AppenderRef ref="Console"/>
        </Root>
    </Loggers>
</Configuration>
```

### 5. Migrate logging config: create `src/test/resources/log4j2-test.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout charset="UTF-8"
                           pattern="%-4r [%t] %-5p %c %x - %m%n"/>
        </Console>
    </Appenders>
    <Loggers>
        <Logger name="io.netty" level="WARN"/>
        <Logger name="org.eclipse.milo" level="WARN"/>
        <Root level="DEBUG">
            <AppenderRef ref="Console"/>
        </Root>
    </Loggers>
</Configuration>
```

### 6. Delete old config files

- Delete `src/main/resources/log4j.properties`
- Delete `src/test/resources/log4j.properties`

### 7. Build, test, install

```bash
mvn clean install
```

## Files Changed

| File | Action |
|------|--------|
| `pom.xml` | Update parent version, update http-server version, bump own version |
| `src/main/resources/log4j2.xml` | Create (migrated from log4j.properties) |
| `src/test/resources/log4j2-test.xml` | Create (migrated from log4j.properties) |
| `src/main/resources/log4j.properties` | Delete |
| `src/test/resources/log4j.properties` | Delete |
