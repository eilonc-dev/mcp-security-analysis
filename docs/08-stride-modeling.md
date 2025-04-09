## 8. Threat Modeling (STRIDE)

Applying the STRIDE threat modeling framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) helps categorize the potential security risks within the MCP ecosystem identified in the preceding sections.

### 8.1. Spoofing

Threats related to illegitimate impersonation:

*   **Client/Server Impersonation:** Malicious entities could impersonate legitimate Clients or Servers if authentication is weak or absent ([Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport), [Section 6.2](./06-trust-boundaries.md#62-hostclient---mcp-server)). This is especially relevant over insecure transports or with inadequate credential handling (e.g., stdio environment variables - [Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport)).
*   **Capability Spoofing:** During initialization, a Client or Server might falsely claim capabilities it doesn't securely support or intend to honor ([Sections 3.2](./03-protocol-interactions.md#32-lifecycle-management-initialize-shutdown-exit), [4.1](./04-data-structures.md#41-capabilities), [7.1](./07-security-considerations-per-component.md#71-initialization--lifecycle-initialize-notificationsinitialized)).
*   **MIME Type Spoofing:** A malicious Server could provide a misleading `mimeType` for resource content to trick the Client into unsafe handling ([Section 4.2](./04-data-structures.md#42-resources)).
*   **Misleading UI (Host):** The Host UI could fail to accurately attribute actions/data to the correct Server, effectively spoofing the origin from the user's perspective ([Section 6.1](./06-trust-boundaries.md#61-user---hostclient-ui)).
*   **Misleading Descriptions/Annotations:** Servers could provide false tool descriptions or annotations to trick users/LLMs into invoking harmful tools ([Sections 4.3](./04-data-structures.md#43-tools), [7.3](./07-security-considerations-per-component.md#73-tools-toolslist-toolscall-notifications)).

### 8.2. Tampering

Threats related to unauthorized modification of data or code:

*   **Message Tampering (Transport):** Modification of MCP messages in transit if the transport layer is not secure (e.g., plain HTTP/WS, unprotected stdio) ([Section 6.2](./06-trust-boundaries.md#62-hostclient---mcp-server)).
*   **Resource Content Tampering:** If a Server's access controls are bypassed or flawed, malicious Clients could potentially modify resources (though MCP core focuses on read; write often implemented via Tools).
*   **Tool Argument Tampering:** Malicious Clients could provide malformed or unexpected arguments to `tools/call` to induce unintended behavior if server-side validation is weak ([Sections 4.3](./04-data-structures.md#43-tools), [7.3](./07-security-considerations-per-component.md#73-tools-toolslist-toolscall-notifications), [9.2](./09-implementation-insights.md#92-python-sdk-tool-argument-validation-toolscall), [9.4](./09-implementation-insights.md#94-typescript-server-examples-tool-argument-validation-toolscall)).
*   **Prompt Argument Tampering:** Malicious Clients providing crafted arguments to `prompts/get` could potentially exploit argument injection vulnerabilities on the Server ([Section 4.4](./04-data-structures.md#44-prompts)).
*   **Sampling Prompt Tampering:** Malicious Servers providing crafted `messages` or `systemPrompt` to `sampling/createMessage` could manipulate the Client's LLM behavior ([Sections 4.5](./04-data-structures.md#45-sampling-client-feature), [7.5](./07-security-considerations-per-component.md#75-sampling-samplingcreatemessage)).
*   **State Management Tampering:** Manipulation of session state, request IDs, progress tokens, or pagination cursors if not handled securely ([Sections 3.1](./03-protocol-interactions.md#31-base-message-structures-json-rpc-20), [4.7](./04-data-structures.md#47-utility-features), [6.2](./06-trust-boundaries.md#62-hostclient---mcp-server)).

### 8.3. Repudiation

Threats related to denying actions performed:

*   **Lack of Auditing:** Insufficient logging on Client or Server side makes it difficult to prove whether a specific tool call, resource access, or sampling request occurred or who initiated it (Implicit, related to Logging in [Section 7.8](./07-security-considerations-per-component.md#78-utilities-logging-pagination-cancellation-progress-ping-completion), needs explicit Logging/Monitoring section).
*   **Client Action Repudiation:** A Client could potentially deny initiating a harmful tool call if logging is inadequate and user consent wasn't properly recorded.
*   **Server Action Repudiation:** A Server could deny having sent a malicious sampling request or faulty resource data if logging is insufficient.

*Note: Robust logging and clear user consent records are the primary mitigations.* 

### 8.4. Information Disclosure

Threats related to exposure of sensitive information:

*   **Eavesdropping (Transport):** Interception of MCP messages containing sensitive data (arguments, resource content, tokens) over insecure transports ([Section 6.2](./06-trust-boundaries.md#62-hostclient---mcp-server)).
*   **Information Leakage (`clientInfo`/`serverInfo`):** Exposing potentially sensitive software versions during initialization ([Sections 3.2](./03-protocol-interactions.md#32-lifecycle-management-initialize-shutdown-exit), [7.1](./07-security-considerations-per-component.md#71-initialization--lifecycle-initialize-notificationsinitialized)).
*   **Error Message Leakage:** Leaking internal system details or sensitive data in JSON-RPC `error` objects (`message` or `data` fields) ([Sections 3.1](./03-protocol-interactions.md#31-base-message-structures-json-rpc-20), [4.3](./04-data-structures.md#43-tools), [6.4](./06-trust-boundaries.md#64-mcp-server---external-systems)).
*   **Log Data Leakage:** Sensitive data (credentials, PII, request details) being included in logs sent via `notifications/message` or logged locally ([Sections 4.7](./04-data-structures.md#47-utility-features), [7.8](./07-security-considerations-per-component.md#78-utilities-logging-pagination-cancellation-progress-ping-completion), [10](./10-summary-hotspots.md)).
*   **Resource Listing Leakage:** `resources/list` potentially revealing existence or metadata of sensitive resources even if content access is restricted ([Section 4.2](./04-data-structures.md#42-resources)).
*   **Resource Content Exposure:** Unauthorized access to sensitive resource content via `resources/read` due to weak access controls or path traversal vulnerabilities ([Sections 4.2](./04-data-structures.md#42-resources), [7.2](./07-security-considerations-per-component.md#72-resources-resourceslist-resourcesread-resourcestemplateslist-resourcessubscribe-notifications)).
*   **Tool Output Leakage:** Tools returning sensitive data from external systems or internal state in their `content` result ([Section 4.3](./04-data-structures.md#43-tools)).
*   **Prompt Content Exposure:** Sensitive information embedded in prompt templates or generated via `prompts/get` ([Section 4.4](./04-data-structures.md#44-prompts)).
*   **Sampling Prompt/Response Leakage:** Sensitive data flowing from Server->Client in `sampling/createMessage` prompts or Client->Server in responses ([Sections 4.5](./04-data-structures.md#45-sampling-client-feature), [7.5](./07-security-considerations-per-component.md#75-sampling-samplingcreatemessage)).
*   **Root Information Disclosure:** Client exposing sensitive filesystem structure information via `roots/list` ([Sections 4.6](./04-data-structures.md#46-roots-client-feature), [7.6](./07-security-considerations-per-component.md#76-roots-rootslist-notifications)).
*   **Token Leakage:** Improper handling/storage of OAuth tokens (Client) or insecure `redirect_uri` validation (Server) leading to token exposure ([Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport)).
*   **Completion Suggestion Leakage:** `completion/complete` suggesting sensitive filenames, user data, etc. ([Section 4.7](./04-data-structures.md#47-utility-features)).

### 8.5. Denial of Service (DoS)

Threats related to preventing legitimate use:

*   **Request Flooding:** Overwhelming Client or Server with excessive requests (`initialize`, `resources/list`, `tools/call`, `ping`, etc.) or notifications (`notifications/cancelled`, `notifications/progress`, `notifications/message`) ([Sections 3.1](./03-protocol-interactions.md#31-base-message-structures-json-rpc-20), [3.2](./03-protocol-interactions.md#32-lifecycle-management-initialize-shutdown-exit), [4.2](./04-data-structures.md#42-resources), [4.3](./04-data-structures.md#43-tools), [4.5](./04-data-structures.md#45-sampling-client-feature), [4.7](./04-data-structures.md#47-utility-features)).
*   **Large Request Payloads:** Sending large capability objects during init, large resource requests (`resources/read`), large tool arguments (`tools/call`), or large base64 blobs (`blob` in resource content/tool results) causing resource exhaustion (memory, CPU) ([Sections 3.2](./03-protocol-interactions.md#32-lifecycle-management-initialize-shutdown-exit), [4.2](./04-data-structures.md#42-resources), [4.3](./04-data-structures.md#43-tools), [4.5](./04-data-structures.md#45-sampling-client-feature)).
*   **Subscription Storms:** Client subscribing to numerous or frequently changing resources, overwhelming the Server with update checks and notifications (`notifications/resources/updated`) ([Section 4.2](./04-data-structures.md#42-resources)).
*   **Cost Overruns (Client):** Malicious Server triggering excessive, expensive LLM calls via `sampling/createMessage` ([Sections 4.5](./04-data-structures.md#45-sampling-client-feature), [6.3](./06-trust-boundaries.md#63-hostclient---llm-service), [7.5](./07-security-considerations-per-component.md#75-sampling-samplingcreatemessage)).
*   **Resource Locking/Exhaustion (Server):** Tools consuming excessive resources (CPU, memory, network, file handles) or causing deadlocks, potentially triggered by malicious arguments ([Section 4.3](./04-data-structures.md#43-tools)). Improper shutdown leaving orphaned processes ([Section 3.2](./03-protocol-interactions.md#32-lifecycle-management-initialize-shutdown-exit)).
*   **External System DoS:** Server overloading downstream external systems based on excessive Client requests ([Section 6.4](./06-trust-boundaries.md#64-mcp-server---external-systems)).
*   **Batching Abuse:** Sending extremely large batches of requests/notifications ([Section 3.1](./03-protocol-interactions.md#31-base-message-structures-json-rpc-20)).

### 8.6. Elevation of Privilege (EoP)

Threats related to gaining unauthorized capabilities or permissions:

*   **Bypassing Authorization:** Exploiting flaws in server-side access control logic to access unauthorized resources (`resources/read`), tools (`tools/call`), or prompts (`prompts/get`) ([Sections 3.3](./03-protocol-interactions.md#33-authorization-http-transport), [4.2](./04-data-structures.md#42-resources), [4.3](./04-data-structures.md#43-tools), [4.4](./04-data-structures.md#44-prompts), [6.2](./06-trust-boundaries.md#62-hostclient---mcp-server)).
*   **Path Traversal:** Accessing files outside of permitted directories via crafted URIs in `resources/read` ([Sections 4.2](./04-data-structures.md#42-resources), [7.2](./07-security-considerations-per-component.md#72-resources-resourceslist-resourcesread-resourcestemplateslist-resourcessubscribe-notifications), [9.1](./09-implementation-insights.md#91-python-sdk-fileresource-path-validation-resourcesread), [9.3](./09-implementation-insights.md#93-typescript-server-example-filesystem-path-validation-for-file-tools)).
*   **Tool-Based EoP:** Exploiting vulnerabilities (e.g., command injection via arguments) within a tool's implementation to execute commands or access data with the Server's privileges ([Sections 4.3](./04-data-structures.md#43-tools), [7.3](./07-security-considerations-per-component.md#73-tools-toolslist-toolscall-notifications), [6.4](./06-trust-boundaries.md#64-mcp-server---external-systems)).
*   **Bypassing Client Consent:** Client/Host failing to implement mandatory user confirmation for `tools/call` or `sampling/createMessage`, effectively allowing the Server to perform actions the user didn't approve ([Sections 2.6](./02-core-concepts.md#26-stated-security-principles-from-specification), [6.1](./06-trust-boundaries.md#61-user---hostclient-ui), [7.3](./07-security-considerations-per-component.md#73-tools-toolslist-toolscall-notifications), [7.5](./07-security-considerations-per-component.md#75-sampling-samplingcreatemessage)).
*   **OAuth Scope Escalation:** Exploiting flaws in OAuth scope definition or enforcement to gain broader access than authorized by the user ([Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport)).
*   **Insecure Dynamic Client Registration:** Malicious client registering itself with elevated privileges if the registration endpoint is insecure ([Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport)).
*   **Server Internal Boundary EoP:** Vulnerabilities allowing compromise of one server component to affect higher-privileged ones ([Section 6.5](./06-trust-boundaries.md#65-mcp-server-internal-boundaries)). 