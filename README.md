# CryptoCertLoader

**A lightweight, zero-dependency Java utility designed to programmatically intercept remote SSL certificate chains, update the local JVM keystore, and hot-swap the execution context on the fly.**

## Description

The **CryptoCertLoader** application automates the extraction of SSL certificates from a target web API specified at runtime. It inspects the local JVM trust store (`cacerts`), verifies the validity of the existing certificate baseline, and dynamically updates expired or missing certificates. 

By exposing a clean Facade API via `CertUpdater`, it enables seamless integration into enterprise applications, ensuring they can survive upstream SSL certificate rotations without downtime or process restarts.

## Features

* **Dynamic Memory-Resident SSL Hot-Swapping:** Re-initializes and injects the modified `SSLContext` directly into the active JVM memory space on the fly. Network clients leverage updated certificates instantly **without requiring an application restart**.
* **Zero-Bloat Handshake Interception:** Captures remote certificate chains atomically during the secure TLS connection phase using `HttpResponse.BodyHandlers.discarding()`. The payload text is destroyed immediately, preventing memory leaks and heap fragmentation.
* **Context-Aware Header Authorization Routing:** Guarantees protection against connection resets enforced by strict enterprise security perimeters and API Gateways. Authorization tokens (`Basic` or `Bearer`) are injected directly into the initial handshake request, preventing 401/403 drops before encryption completes.
* **Automated Rollback & Backup Pipeline:** Executes a proactive backup of the primary system `cacerts` file using unique timestamp markers (`yyyyMMdd_HHmmss`) before committing updates. Any I/O fault triggers an immediate transaction abort to protect keystore integrity.
* **Intelligent Validity & Hash Mapping:** Generates deterministic unique aliases based on `X500Principal` metadata. It automatically overwrites local certificates if they fail validation checks (`checkValidity`), keeping the local trust store clean and up-to-date.

## Shared Dependency Architecture

This utility is compiled as a standalone **shared library (.jar)**. In accordance with the centralized infrastructure paradigm, it is designed to be placed inside a common `dependencies/` folder located one level above your operational integration applications. This avoids artifact duplication and unifies SSL trust lifecycle management across the entire ecosystem.

---

## Project Structure

The project follows a decoupled Facade design pattern:

* `my.CertUpdater` — The primary entry point and developer-facing Facade class. Provides simplified methods for distinct authentication contexts (`basic`, `token`, `none`).
* `my.KeyStoreManager` — The core engine responsible for low-level networking, programmatic SSL interception, `KeyStore` byte-stream I/O operations, and dynamic `SSLContext` memory hot-swapping.

---

## Quick Start & Integration API

### 1. Installation
Compile the project into a binary shared asset via Maven:
```bash
mvn clean package
```
Move the generated `crypto-cert-loader-0.0.1-SNAPSHOT.jar` into your shared `dependencies/` folder.

### 2. Integration into Client Applications
Invoke the `CertUpdater` facade inside your application's entry orchestration sequence *before* initializing any persistent HTTP networking pools. 

The library will automatically synchronize the physical `cacerts` store and prepare the hot-swapped execution context.

#### Basic Authentication Context
```java
// Pass target URL, username, and password parameters
my.CertUpdater.updateByBasicAuth("https://example.com", "username", "password");
```

#### Token/Bearer Authentication Context
```java
// Pass target URL and raw token signature parameters
my.CertUpdater.updateByToken("https://example.com", "eyJhbGciOiJIUzI1Ni...");
```

#### Public Unauthenticated Context
```java
// Pass target public URL parameter
my.CertUpdater.updateWithoutAuth("https://public-endpoint.com");
```

### 3. Binding to Modern Networking Clients (e.g., Apache HttpClient 5)
Once `CertUpdater` completes its lifecycle routine, extract the updated memory-resident context directly from the utility engine to provision your active network transport layer:

```java
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;

// 1. Fetch the programmatically synchronized context from memory
SSLContext dynamicSslContext = my.KeyStoreManager.getSSLContext();

// 2. Bind the hot-swapped context to the Apache HttpClient socket factory
SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(dynamicSslContext);

// 3. Inject the factory into the connection pool manager
var connManager = PoolingHttpClientConnectionManagerBuilder.create()
        .setSSLSocketFactory(sslSocketFactory)
        .build();
```

---

## Prerequisites

* **Java:** JDK 11 or higher (utilizes native standard Java `HttpClient` components for non-blocking interception).
* **System Permissions:** The executing JVM process must have adequate read/write operating system permissions for the active JDK/JRE security storage directory (`lib/security/cacerts` or `conf/security/cacerts`).
