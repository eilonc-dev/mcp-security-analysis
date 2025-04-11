## 7. Security Considerations per Component

This section consolidates the key security risks and required controls organized by the major MCP components and features.

### 7.1. Initialization & Lifecycle (`initialize`, `notifications/initialized`)

-   **Key Risks:** Capability spoofing/misrepresentation, protocol version downgrade attacks, information leakage (`clientInfo`/`serverInfo`), resource exhaustion during init, state mismatches if `initialized` notification fails.
-   **Required Controls:** Strict validation of negotiated capabilities against actual implementation, secure version negotiation logic, minimize info in `clientInfo`/`serverInfo`, rate limit `initialize` requests, robust state management, enforce request order around `initialize`/`initialized`.
-   **(See [Section 3.2](./03-protocol-interactions.md#32-lifecycle-management-initialize-shutdown-exit), [Section 4.1](./04-data-structures.md#41-capabilities), [Section 6.2](./06-trust-boundaries.md#62-hostclient-mcp-server))**

### 7.2. Resources (`resources/list`, `resources/read`, `resources/templates/list`, `resources/subscribe`, notifications)

-   **Key Risks:** Path traversal via URI manipulation (`resources/read`, `resources/subscribe`), insufficient access control (listing or reading sensitive data), data leakage via metadata in `resources/list`, DoS via large resource requests or subscription storms, insecure client-side handling of received content (`text`/`blob`), URI template injection, MIME type spoofing.
-   **Required Controls (Server):** Rigorous URI validation/canonicalization, enforce authorization *before* list/read/subscribe, filter lists based on permissions, implement size limits/streaming for `resources/read`, rate limit subscriptions and notifications.
-   **Required Controls (Client):** Safely handle/render received content based on MIME type, treat cursors as opaque.
-   **(See [Section 4.2](./04-data-structures.md#42-resources), [Section 5.2](./05-communication-patterns.md#52-resource-discovery-reading), [Section 5.6](./05-communication-patterns.md#56-resource-subscription-update-optional), [Section 6.2](./06-trust-boundaries.md#62-hostclient-mcp-server), [Section 6.4](./06-trust-boundaries.md#64-mcp-server-external-systems), [Section 6.5](./06-trust-boundaries.md#65-mcp-server-internal-boundaries))**

### 7.3. Tools (`tools/list`, `tools/call`, notifications)

-   **Key Risks:** Arbitrary code execution (highest risk), injection attacks via tool `arguments`, insufficient access control, data exfiltration via arguments, output sanitization failures (leading to XSS on client), untrusted tool descriptions/annotations misleading user/LLM, DoS via excessive calls.
-   **Required Controls (Server):** Rigorous input validation against `inputSchema`, strong authorization checks, sanitize output `content`, rate limit `tools/call`, consider sandboxing tool execution.
-   **Required Controls (Client):** Implement mandatory user confirmation (human-in-the-loop) showing tool name and arguments, treat descriptions/annotations as untrusted, handle received `content` safely.
-   **(See [Section 4.3](./04-data-structures.md#43-tools), [Section 5.3](./05-communication-patterns.md#53-tool-discovery-execution), [Section 6.1](./06-trust-boundaries.md#61-user-hostclient-ui), [Section 6.2](./06-trust-boundaries.md#62-hostclient-mcp-server), [Section 6.4](./06-trust-boundaries.md#64-mcp-server-external-systems), [Section 6.5](./06-trust-boundaries.md#65-mcp-server-internal-boundaries))**

### 7.4. Prompts (`prompts/list`, `prompts/get`, notifications)

-   **Key Risks:** Server-side argument injection into templates, insufficient access control (listing/getting prompts), sensitive data exposure in templates or generated messages, misleading prompts tricking user/LLM, unsafe handling of embedded resources.
-   **Required Controls (Server):** Sanitize arguments *before* template insertion, enforce authorization, design templates carefully to avoid data exposure.
-   **Required Controls (Client):** Handle received message `content` (including embedded resources) safely.
-   **(See [Section 4.4](./04-data-structures.md#44-prompts), [Section 5.4](./05-communication-patterns.md#54-prompt-discovery-usage), [Section 6.2](./06-trust-boundaries.md#62-hostclient-mcp-server))**

### 7.5. Sampling (`sampling/createMessage`)

-   **Key Risks:** Bypass of client-side user consent, prompt injection from server manipulating client's LLM, client resource exhaustion (cost/rate limiting), sensitive data leakage (Server->Client in prompt, potentially Client->Server in response), harmful content generation by LLM.
-   **Required Controls (Client):** Implement mandatory user confirmation (view/edit prompt), sanitize/validate server-provided prompt content before sending to LLM, implement rate limiting/cost controls, filter/moderate LLM responses before returning to server or user.
-   **(See [Section 4.5](./04-data-structures.md#45-sampling-client-feature), [Section 5.5](./05-communication-patterns.md#55-server-initiated-sampling), [Section 6.1](./06-trust-boundaries.md#61-user-hostclient-ui), [Section 6.2](./06-trust-boundaries.md#62-hostclient-mcp-server), [Section 6.3](./06-trust-boundaries.md#63-hostclient-llm-service))**

### 7.6. Roots (`roots/list`, notifications)

-   **Key Risks:** Information disclosure (filesystem structure), exposure of unintended/sensitive directories by client.
-   **Required Controls (Client):** Expose only intended roots, ideally with user consent per root, validate exposed URIs.
-   **Required Controls (Server):** Respect root boundaries when forming resource URIs (though enforcement relies on resource access controls).
-   **(See [Section 4.6](./04-data-structures.md#46-roots-client-feature), [Section 6.1](./06-trust-boundaries.md#61-user-hostclient-ui), [Section 6.2](./06-trust-boundaries.md#62-hostclient-mcp-server))**

### 7.7. Authorization (HTTP - OAuth 2.1)

-   **Key Risks:** Insecure transport (HTTP instead of HTTPS), weak PKCE implementation, improper redirect URI validation (Open Redirect), insecure client-side token storage, weak server-side token validation (expiry, scope, signature), insecure dynamic client registration, third-party auth complexities.
-   **Required Controls:** Enforce HTTPS, use robust PKCE libraries, perform strict redirect URI matching, use secure storage for tokens (client), implement thorough token validation (server), secure registration endpoints, carefully implement third-party auth flows.
-   **(See [Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport), [Section 6.2](./06-trust-boundaries.md#62-hostclient-mcp-server))**

### 7.8. Utilities (Logging, Pagination, Cancellation, Progress, Ping, Completion)

-   **Key Risks:** Sensitive data leakage in logs (`notifications/message`), DoS via log/notification flooding (logs, progress, cancellation), insecure pagination cursor handling, information leakage via completion suggestions.
-   **Required Controls:** Sanitize all log data (Server), rate limit logs/notifications (Server/Client), validate cursors (Server), treat cursors as opaque (Client), authorize and filter completion requests/responses (Server).
-   **(See [Section 4.7](./04-data-structures.md#47-utility-features))**