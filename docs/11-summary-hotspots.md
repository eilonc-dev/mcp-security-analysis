## 11. Summary & Security Hotspots

This section summarizes the key security findings and highlights the most critical areas (hotspots) requiring careful attention during implementation and deployment of MCP Clients and Servers.

### 11.1. Key Findings Summary

-   **Trust Boundaries are Key:** Security posture heavily depends on controls at boundaries (User<->Client, Client<->Server, Server<->External).
-   **Server-Side Validation is Crucial:** Servers MUST validate all client input (URIs, tool args, prompt args) to prevent injection, traversal, etc.
-   **Client Consent is Paramount:** Features like `tools/call` and especially `sampling` REQUIRE robust, non-bypassable user consent flows in the client.
-   **Tools == High Risk:** The `tools/call` mechanism introduces significant risk (code execution); requires strict validation, least privilege, and user consent.
-   **Transport Security is Foundational:** Unsecured transports undermine all other security efforts.
-   **Logging Needs Care:** Logging (via `notifications/message` or locally) can leak sensitive data if not filtered/masked.
-   **Capability Negotiation is Nuanced:** Relying solely on declared capabilities for security decisions is unsafe.

### 11.2. Security Hotspots & Recommendations

1.  **Tool Implementation (`tools/call`):**
    *   **Risk:** Arbitrary Code Execution, EoP, Tampering.
    *   **Recommendation:** **HIGHEST PRIORITY.** Implement strict input validation (schema + value constraints). Apply least privilege; avoid shell execution if possible. Sanitize outputs. Consider sandboxing. Mandate Client-side user confirmation.
    *   **(See [Section 4.3](./04-data-structures.md#43-tools), [Section 7.3](./07-security-considerations-per-component.md#73-tools-toolslist-toolscall-notifications), [Section 9.2](./09-attack-scenarios.md#scenario-tool-argument-injection), [Section 9.6](./09-attack-scenarios.md#scenario-tool-vulnerability-exploitation))**

2.  **Resource Access (`resources/read`):**
    *   **Risk:** Path Traversal, Information Disclosure.
    *   **Recommendation:** Implement rigorous URI validation and canonicalization on the server *before* filesystem access. Ensure paths are confined to allowed roots. Enforce authorization.
    *   **(See [Section 4.2](./04-data-structures.md#42-resources), [Section 7.2](./07-security-considerations-per-component.md#72-resources-resourceslist-resourcesread-resourcestemplateslist-resourcessubscribe-notifications), [Section 9.4](./09-attack-scenarios.md#scenario-path-traversal-via-crafted-resourcesread-uri))**

3.  **Client Consent Implementation (`sampling/createMessage`, `tools/call`):**
    *   **Risk:** EoP (Server acting as user via Client), Information Disclosure (from Client context).
    *   **Recommendation:** Clients MUST implement clear, non-bypassable user confirmation dialogs displaying *all* relevant information (full prompt, tool name/args). Securely log consent decisions.
    *   **(See [Section 4.5](./04-data-structures.md#45-sampling-client-feature), [Section 6.1](./06-trust-boundaries.md#61-user-hostclient-ui), [Section 7.5](./07-security-considerations-per-component.md#75-sampling-samplingcreatemessage), [Section 9.6](./09-attack-scenarios.md#scenario-bypassing-client-consent-for-sampling))**

4.  **Transport Security & Authentication:**
    *   **Risk:** Spoofing, Tampering, Information Disclosure.
    *   **Recommendation:** MANDATE TLS (HTTPS/WSS) with certificate validation for non-local connections. Implement strong authentication where appropriate (e.g., OAuth 2.1).
    *   **(See [Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport), [Section 6.2](./06-trust-boundaries.md#62-hostclient-mcp-server), [Section 9.1](./09-attack-scenarios.md#scenario-malicious-server-imitation), [Section 9.2](./09-attack-scenarios.md#scenario-in-transit-message-modification-unsecured-transport))**

5.  **Logging Practices:**
    *   **Risk:** Information Disclosure (credentials, PII).
    *   **Recommendation:** Filter/mask sensitive data *before* logging. Use appropriate log levels. Secure log transport and storage.
    *   **(See [Section 4.7](./04-data-structures.md#47-utility-features), [Section 7.8](./07-security-considerations-per-component.md#78-utilities-logging-pagination-cancellation-progress-ping-completion), [Section 9.4](./09-attack-scenarios.md#scenario-sensitive-data-leakage-via-logs))**

6.  **Input Size Limits & Rate Limiting:**
    *   **Risk:** Denial of Service.
    *   **Recommendation:** Implement application-level limits on request/parameter sizes and request frequency.
    *   **(See [Section 7.8](./07-security-considerations-per-component.md#78-utilities-logging-pagination-cancellation-progress-ping-completion), [Section 9.5](./09-attack-scenarios.md#scenario-request-flooding), [Section 9.5](./09-attack-scenarios.md#scenario-resource-exhaustion-via-large-payload))** 