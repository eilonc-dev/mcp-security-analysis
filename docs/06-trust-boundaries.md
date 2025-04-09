## 6. Trust Boundaries

A trust boundary is a point in the system where data or execution transitions from one trust level to another. Identifying these boundaries is crucial for determining where security controls (authentication, authorization, input validation, output encoding, etc.) are most needed. In the MCP ecosystem, several key boundaries exist:

*   **User <-> Host/Client UI:** The interface where the user interacts with the MCP-enabled application. Trust depends on the Host application's security and UI/UX clarity.
*   **Host/Client <-> MCP Server:** The core MCP communication channel (over transports like stdio, HTTP/S, WebSockets). This is a major boundary, often between different processes or machines, potentially involving untrusted servers.
*   **Host/Client <-> LLM Service:** When using the `sampling` feature, the Host/Client communicates with an external LLM API. Trust relies on the LLM provider's security and the API contract.
*   **MCP Server <-> External Systems:** MCP Servers often act as intermediaries, accessing databases, APIs, filesystems, or other resources based on MCP requests (especially for `resources/read` and `tools/call`).
*   **MCP Server Internal Boundaries:** Within the server itself, boundaries exist between request handling logic, tool execution logic, resource access logic, and data stores.

Understanding the assumptions and risks at each boundary is critical for designing secure MCP implementations.

### 6.1. User <-> Host/Client UI

-   **Description:** The interface presented by the Host application (IDE, chat client) where the user interacts with MCP features, implicitly or explicitly.
-   **Trust Assumptions:** The user generally trusts the Host application they are running, but may not fully trust all *extensions* or *servers* it connects to via MCP. The Host application is trusted to accurately represent information and actions related to MCP.
-   **Key Risks:**
    *   **Misleading UI:** The Host UI might not clearly indicate which server is providing a resource/tool/prompt, or what actions a tool/sampling request will perform, leading the user to approve unsafe operations.
    *   **Lack of Consent/Control:** The Host might not implement proper consent flows (as recommended by the MCP spec) for resource access, tool execution, or sampling, leading to unexpected data exposure or actions.
    *   **UI Redressing/Clickjacking:** Standard web/UI vulnerabilities in the Host application could be exploited to trick the user into unintended MCP-related actions.
    *   **Host Compromise:** If the Host application itself is compromised, all MCP interactions become untrustworthy.
-   **Required Controls (Host Application Responsibility):**
    *   **Clear Attribution:** Clearly display the source (MCP Server) of resources, tools, and prompts.
    *   **Explicit Consent:** Implement robust, understandable confirmation dialogs for:
        *   Connecting to new MCP Servers.
        *   Granting access to filesystem roots (`roots` feature).
        *   Authorizing OAuth flows ([Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport)).
        *   Executing `tools/call` requests, showing the tool name and arguments.
        *   Approving `sampling/createMessage` requests, showing the prompt content.
    *   **Secure UI Development:** Follow standard secure UI practices to prevent injection, clickjacking, etc.
    *   **Input Sanitization:** Sanitize any user input that might become part of MCP request parameters (e.g., arguments for `prompts/get`).
    *   **Output Encoding/Sanitization:** Safely render information received from MCP Servers (e.g., resource content, tool results, log messages) to prevent XSS if displayed in the UI.

### 6.2. Host/Client <-> MCP Server

-   **Description:** The communication channel where JSON-RPC messages are exchanged between the client (running within the Host) and the MCP server. This occurs over a transport like stdio, HTTP/S, or WebSockets.
-   **Trust Assumptions:** This is often the least trusted boundary, especially if connecting to third-party or public MCP servers. The client cannot inherently trust the server, and the server cannot inherently trust the client.
-   **Key Risks:**
    *   **Untrusted Server:** Malicious server attempts to exploit client vulnerabilities via crafted responses/notifications, requests unauthorized actions (e.g., sampling), provides malicious resource content/tool results, lies about capabilities, causes DoS.
    *   **Untrusted Client:** Malicious client attempts to exploit server vulnerabilities via crafted requests/notifications, accesses unauthorized resources/tools, bypasses auth, lies about capabilities, causes DoS (e.g., request flooding, large requests).
    *   **Eavesdropping/Tampering (Transport):** If the transport layer is not secured (e.g., plain HTTP/WS instead of HTTPS/WSS, unencrypted stdio), messages can be intercepted or modified in transit.
    *   **Authentication/Authorization Bypass:** Weak or missing authentication/authorization mechanisms allow unauthorized access.
    *   **Input Validation Failures:** Failure on either side to validate incoming message parameters (`params`) can lead to various injection attacks or crashes.
    *   **Information Leakage:** Sensitive data might be leaked via error messages, log messages, resource/tool/prompt metadata, or even timing side channels.
-   **Required Controls:**
    *   **Transport Security:** Mandate secure transports (HTTPS, WSS) for non-local connections. Protect stdio communication if applicable (e.g., ensure only intended processes can connect).
    *   **Authentication:** Implement strong authentication for both client and server where necessary (e.g., OAuth 2.1 for HTTP as per spec ([Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport)), environment/token auth for stdio).
    *   **Authorization:** Enforce granular authorization checks on the server *before* performing actions (listing/reading resources, calling tools, getting prompts). Use OAuth scopes or equivalent mechanisms.
    *   **Rigorous Input Validation (Both Sides):** Both client and server MUST validate all incoming request/notification parameters against the expected schema/types/constraints before processing. This includes URIs, tool arguments, prompt arguments, log levels, progress tokens, etc.
    *   **Output Encoding/Sanitization (Both Sides):** Data sent across the boundary (e.g., resource content, tool results, prompt messages, error details, log data) should be appropriately sanitized or encoded to prevent interpretation issues (like XSS) on the receiving end.
    *   **Capability Enforcement:** Both sides MUST check received requests/notifications against the capabilities negotiated during initialization.
    *   **State Management:** Securely manage session state, request IDs, subscription tokens, progress tokens to prevent reuse or hijacking.
    *   **Rate Limiting/DoS Protection:** Both sides should implement rate limiting on incoming requests/notifications.
    *   **Least Privilege:** Design both client and server components to operate with the minimum necessary privileges.

### 6.3. Host/Client <-> LLM Service

-   **Description:** The interface between the Host/Client application and the external Large Language Model service provider API (e.g., OpenAI, Anthropic, Google AI). This is primarily relevant for the `sampling` feature but also if the client uses LLMs for interpreting user requests before forming MCP calls.
-   **Trust Assumptions:** The Host/Client generally trusts the LLM provider to adhere to its API contract, privacy policy, and security practices. However, the specific model's behavior might be unpredictable (hallucinations, potential for harmful content generation).
-   **Key Risks:**
    *   **Data Privacy/Confidentiality:** Sensitive data sent within prompts (originating from the user, the Host application, or even the MCP Server via `sampling/createMessage`) is exposed to the LLM provider. Risks include inadequate data handling by the provider, breaches, or use for model training contrary to policy/user consent.
    *   **Prompt Injection:** Malicious input (potentially originating from an untrusted MCP Server via `sampling/createMessage`) could manipulate the LLM into unintended actions, revealing sensitive information from its context, or generating harmful content.
    *   **Insecure API Key Handling:** Client needs to securely store and use API keys/credentials for the LLM service.
    *   **Harmful Content Generation:** The LLM might generate biased, inaccurate, offensive, or otherwise harmful content, which the client then needs to handle appropriately (filter, warn user, potentially block from being sent back to MCP Server).
    *   **Cost Overruns:** Uncontrolled or excessive API calls (potentially triggered by a malicious MCP server via `sampling`) could lead to high costs.
-   **Required Controls (Host/Client Responsibility):**
    *   **Secure Credential Management:** Protect LLM API keys using secure storage (e.g., OS keychain, secrets management systems).
    *   **Data Minimization:** Send only necessary data to the LLM API. Consider filtering or anonymizing sensitive information before inclusion in prompts if possible.
    *   **Clear User Consent/Policy:** Inform users about which LLM provider is used and how their data is handled (referencing provider policies).
    *   **Input Sanitization/Validation:** Sanitize/validate data *before* including it in prompts sent to the LLM, especially if it originates from untrusted sources like an MCP server.
    *   **Output Filtering/Moderation:** Implement mechanisms to detect and handle harmful or inappropriate content generated by the LLM before displaying it or sending it back to an MCP server.
    *   **Rate Limiting/Cost Controls:** Implement client-side controls to limit the frequency and potential cost of LLM API calls, especially those triggered via `sampling`.
    *   **Context Separation:** Be careful about the context provided to the LLM; avoid including sensitive internal application state or unrelated user data unless explicitly necessary and consented to.

### 6.4. MCP Server <-> External Systems

-   **Description:** The interface between the MCP Server and any external systems it interacts with to provide resources or execute tools. This includes databases, external APIs, local filesystems, version control systems, etc.
-   **Trust Assumptions:** Highly variable. The Server might fully trust its own database but treat external third-party APIs with caution. Trust in the local filesystem depends on the server's deployment environment and permissions.
-   **Key Risks:**
    *   **Credential Management:** Server needs to securely store and use credentials (API keys, DB passwords, service account keys) for external systems.
    *   **Injection Attacks:** User/Client-controlled input from MCP requests (e.g., resource URIs, tool arguments) might be insecurely used in queries or commands sent to external systems (SQL injection, command injection, SSRF if accessing URLs).
    *   **Data Exposure:** Server might inadvertently expose sensitive data from external systems via MCP resource content, tool results, prompt messages, or log messages.
    *   **External System Compromise:** A compromised external system could return malicious data to the server, which might then be relayed to the MCP client.
    *   **Denial of Service:** Server might overload external systems with requests, potentially triggered by excessive MCP client requests.
    *   **Excessive Permissions:** The server process might have overly broad permissions on the filesystem or other external resources it accesses.
-   **Required Controls (MCP Server Responsibility):**
    *   **Secure Credential Management:** Store external system credentials securely (secrets management, environment variables, secure configuration).
    *   **Input Validation and Parameterization:** Rigorously validate and sanitize any input originating from MCP requests before using it to interact with external systems. Use parameterized queries (for SQL), safe file path handling, and proper escaping for shell commands or API calls.
    *   **Output Sanitization/Filtering:** Filter or sanitize data retrieved from external systems before including it in MCP responses or logs.
    *   **Least Privilege:** Run the server process with the minimum necessary permissions to access required external systems/files.
    *   **Network Segmentation/Firewalls:** Restrict the server's outbound network access to only necessary external systems.
    *   **Error Handling:** Handle errors from external systems gracefully without leaking sensitive details.
    *   **Rate Limiting:** Implement rate limiting for requests to external systems, potentially tied to MCP client rate limits.
    *   **Validate External System Responses:** Treat data from external systems (especially third-party APIs) as potentially untrusted; validate or sanitize it before use.

### 6.5. MCP Server Internal Boundaries

-   **Description:** Interfaces between different logical components *within* the MCP server process itself (e.g., between the main request handler, authorization logic, resource provider modules, tool execution sandbox, data access layers).
-   **Trust Assumptions:** While often within the same process, different components might operate with different privileges or handle data of varying sensitivity. Trust should not be implicitly assumed between components.
-   **Key Risks:**
    *   **Privilege Escalation:** A vulnerability in a lower-privileged component (e.g., request parsing) could potentially allow an attacker to influence or control higher-privileged components (e.g., tool execution, direct filesystem access).
    *   **Data Flow Violations:** Sensitive data (e.g., credentials for external systems, user data from resources) might incorrectly flow between components and get logged or returned inappropriately.
    *   **Bypassed Controls:** Authorization or validation logic might be incorrectly bypassed if components call each other directly without going through the proper checks.
    *   **Insecure State Management:** Shared state between components might be manipulated in unexpected ways.
-   **Required Controls (MCP Server Responsibility):**
    *   **Modular Design:** Structure the server code into well-defined modules with clear responsibilities and interfaces.
    *   **Centralized Input Validation:** Perform initial validation of MCP request parameters at the entry point before passing data to internal components.
    *   **Centralized Authorization:** Enforce authorization checks consistently before dispatching requests to resource/tool/prompt handling logic.
    *   **Data Flow Analysis:** Carefully track how sensitive data flows between components, ensuring it's only accessed where necessary and not leaked (e.g., into logs or generic error messages).
    *   **Sandboxing (for Tools):** If possible and applicable, execute high-risk tool logic in a sandboxed environment with restricted permissions (e.g., separate process, container, specific language-level sandboxing).
    *   **Defensive Programming:** Components should validate assumptions about data received from other internal components, especially if trust levels differ.
    *   **Secure State Handling:** Protect shared state using appropriate synchronization mechanisms and validate state transitions. 