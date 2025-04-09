## 3. Protocol Interactions & Message Deep Dive

This section details the fundamental JSON-RPC 2.0 message structures used by MCP, lifecycle management, and authorization basics.

### 3.1. Base Message Structures (JSON-RPC 2.0)

MCP uses standard JSON-RPC 2.0 for all messages. Key requirements and constraints:

-   **Requests:**
    -   Sent by either Client or Server to initiate an operation.
    -   `jsonrpc`: "2.0"
    -   `id`: `string` or `number` (Mandatory, **MUST NOT** be `null`). Request IDs must be unique per session for the sender.
    -   `method`: `string` (Name of the method to be invoked).
    -   `params`: `object` (Optional parameters for the method).
-   **Responses:**
    -   Sent in reply to a Request.
    -   `jsonrpc`: "2.0"
    -   `id`: `string` or `number` (Must match the ID of the corresponding Request).
    -   `result`: `object` (Present on success, contains the operation result).
    -   `error`: `object` (Present on failure). Must contain `code` (`integer`), `message` (`string`), and optionally `data` (`unknown`).
    -   A response **MUST** contain either `result` or `error`, but not both.
-   **Notifications:**
    -   Sent by either Client or Server as a one-way message (no response expected).
    -   `jsonrpc`: "2.0"
    -   `method`: `string` (Name of the notification event).
    -   `params`: `object` (Optional parameters for the notification).
    -   **MUST NOT** include an `id`.
-   **Batching:**
    -   Implementations **MUST** support *receiving* batched requests/notifications (sent as a JSON array).
    -   Implementations **MAY** support *sending* batches.

**Security Considerations (Base JSON-RPC):**

-   **Request ID Uniqueness:** While mandated, improper handling could lead to response mismatches or potential replay attacks if IDs are predictable or reused insecurely within a session.
-   **Error Handling:** Sensitive information could be leaked in `error` messages (`message` or `data` fields) if not carefully constructed.
-   **Batching Complexity:** Handling batches correctly is crucial. Errors in processing one part of a batch should not necessarily halt others, but error reporting needs to be precise. Large batches could be used for DoS attempts.

### 3.2. Lifecycle Management (Initialize, Shutdown, Exit)

The connection follows a defined lifecycle:

1.  **Initialization Phase:**
    *   **Trigger:** Client sends `initialize` request to Server.
    *   **Purpose:** Negotiate protocol version, exchange capabilities, share implementation info (`clientInfo`, `serverInfo`).
    *   **Client `initialize` Params:** `protocolVersion`, `capabilities` (Client's offered features like `roots`, `sampling`), `clientInfo` (`name`, `version`).
    *   **Server `initialize` Result:** `protocolVersion` (Agreed version), `capabilities` (Server's offered features like `logging`, `prompts`, `resources`, `tools`), `serverInfo` (`name`, `version`).
    *   **Protocol Version Negotiation:** Client proposes version (latest supported). Server responds with the same version if supported, otherwise its latest supported version. Client SHOULD disconnect if server's version is unsupported.
    *   **Capability Negotiation:** Defines which optional features (Resources, Tools, Prompts, Sampling, Logging, Roots, etc.) are available for the session. Specific sub-capabilities (e.g., `listChanged`, `subscribe`) are also negotiated here.
    *   **Confirmation:** Client sends `notifications/initialized` notification after receiving a successful `initialize` response.
    *   **Restrictions:**
        *   `initialize` request MUST NOT be batched.
        *   Client SHOULD NOT send other requests (except ping) before server responds to `initialize`.
        *   Server SHOULD NOT send requests (except ping, logging) before receiving `notifications/initialized`.
2.  **Operation Phase:**
    *   Normal exchange of requests, responses, and notifications based on negotiated capabilities and protocol version.
3.  **Shutdown Phase:**
    *   Clean termination initiated usually by the Client.
    *   No specific protocol messages.
    *   Relies on transport layer closure (e.g., closing stdio streams, closing HTTP connections).
    *   Specification provides guidance for graceful shutdown with stdio (close input, wait/SIGTERM, wait/SIGKILL).

**Security Considerations (Lifecycle):**

-   **Initialization Vulnerabilities:**
    *   **Capability Spoofing/Misrepresentation:** A malicious Client or Server could lie about its `capabilities` or `Info`, potentially tricking the other party into insecure operations or attempting to enable features it doesn't securely support.
    *   **Version Downgrade Attacks:** If negotiation logic isn't strict, an attacker might force the use of an older, potentially less secure protocol version.
    *   **Resource Exhaustion during Init:** A flood of `initialize` requests or large capability objects could cause DoS.
    *   **Information Leakage:** `clientInfo` and `serverInfo` could leak potentially sensitive details about the software versions in use, aiding attackers in finding known exploits.
-   **Improper Shutdown:** Failure to shut down gracefully (especially with stdio) could leave orphaned server processes, potentially consuming resources or holding locks.
-   **State Mismatches:** If the `notifications/initialized` is lost or mishandled, the Client and Server might have different understandings of the session state, leading to errors or unexpected behavior.
-   **Capability Enforcement:** The protocol relies on implementations to *honor* the negotiated capabilities. A compromised or malicious participant could ignore the negotiation and attempt to use features that weren't agreed upon.

### 3.3. Authorization (HTTP Transport)

Authorization is optional but specified for HTTP-based transports. Implementations using stdio SHOULD retrieve credentials from the environment instead.

-   **Standard:** Based on OAuth 2.1 (IETF Draft) with PKCE mandatory for all clients.
-   **Trigger:** Server responds with HTTP 401 Unauthorized when authorization is required.
-   **Flow:** Standard OAuth 2.1 Authorization Code Grant flow with PKCE.
    1.  Client receives 401.
    2.  Client generates `code_verifier` and `code_challenge`.
    3.  Client directs user-agent (browser) to Server's authorization endpoint (`/authorize` by default, or discovered via metadata) with `code_challenge`.
    4.  User authenticates and authorizes the Client via the Server.
    5.  Server redirects user-agent back to Client's registered `redirect_uri` with an `authorization_code`.
    6.  Client receives `authorization_code`.
    7.  Client makes a POST request to the Server's token endpoint (`/token` by default, or discovered) including the `authorization_code` and the original `code_verifier`.
    8.  Server verifies the code and verifier, issues an `access_token` (and optionally a `refresh_token`).
    9.  Client includes the `access_token` in the `Authorization: Bearer <token>` header for subsequent MCP requests over HTTP.
-   **Metadata Discovery (RFC 8414):**
    *   Clients MUST attempt discovery via `GET /.well-known/oauth-authorization-server` relative to the *authorization base URL* (Server URL with path removed).
    *   Clients SHOULD include `MCP-Protocol-Version` header in discovery requests.
    *   Servers SHOULD provide metadata; if not, Clients MUST fallback to default paths (`/authorize`, `/token`, `/register`).
-   **Dynamic Client Registration (RFC 7591):**
    *   Clients and Servers SHOULD support dynamic registration via the registration endpoint (`/register` by default or discovered).
    *   Allows clients to obtain `client_id` (and potentially `client_secret` for confidential clients) automatically.
    *   Servers not supporting it require alternative methods (hardcoded ID, manual user entry).
-   **Access Token Usage:**
    *   MUST be sent in `Authorization: Bearer <token>` header for every HTTP request.
    *   MUST NOT be sent in URI query string.
    *   Servers MUST validate tokens (signature, expiry, scope) and respond with 401/403 on failure.
-   **Third-Party Authorization:** Servers MAY delegate auth to a third-party OAuth server, acting as a client to the third-party and an authorization server to the MCP client. Requires careful session binding and validation.

**Security Considerations (Authorization):**

-   **Transport Security:** All authorization endpoints MUST use HTTPS.
-   **PKCE Implementation:** Correct implementation is crucial to prevent authorization code interception attacks.
-   **Redirect URI Validation:** Servers MUST strictly validate `redirect_uri` against pre-registered values to prevent Open Redirect attacks and token leakage.
-   **Token Storage (Client):** Clients MUST store access and refresh tokens securely (e.g., using OS keychain, encrypted storage).
-   **Token Handling (Server):** Servers SHOULD enforce short token lifetimes, support token rotation (refresh tokens), and securely validate tokens.
-   **Dynamic Client Registration Security:** Unauthenticated or improperly secured registration endpoints could allow malicious clients to register. Servers need robust policies.
-   **Metadata Security:** Relying on potentially unsecured HTTP for discovery (if HTTPS is not enforced) could lead to endpoint spoofing.
-   **Third-Party Auth Risks:** Introduces complexity and reliance on the third-party's security. Session binding must be robust to prevent attacks where a compromised third-party session grants access to MCP.
-   **Scope Management:** Proper definition and enforcement of OAuth scopes are needed to limit the client's access to only what the user authorized (least privilege).
-   **Credential Handling (stdio):** Retrieving credentials from the environment for stdio transport needs careful handling to avoid exposing secrets in logs, process lists, or insecure environment variable storage. 