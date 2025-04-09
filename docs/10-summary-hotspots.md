## 10. Summary of Security Hotspots

Based on the analysis of the protocol specification, communication patterns, and trust boundaries, the following areas represent the most significant security risks and require careful mitigation:

1.  **Tool Execution (`tools/call`) - Arbitrary Code Execution Risk:** This is inherently the highest-risk feature. Servers MUST implement rigorous input validation against the JSON schema, strong authorization checks, output sanitization, and consider sandboxing tool execution environments.

2.  **User Consent & Control (Client/Host Responsibility):** The MCP specification explicitly relies on the client/host application to mediate user consent for potentially sensitive operations like `tools/call` and `sampling/createMessage`, as well as resource access. Failure to implement clear, explicit, and non-bypassable user confirmation flows breaks the security model.

3.  **Resource Access (`resources/read`) - Path Traversal & Access Control:** Servers MUST perform strict validation and canonicalization of resource URIs provided by clients to prevent access to unauthorized files/data (e.g., path traversal). Authorization checks must occur *before* any resource access.

4.  **Input Validation (Client & Server):** Both clients and servers MUST rigorously validate *all* parameters received in requests and notifications against expected types, formats, and constraints. This is crucial to prevent injection attacks (prompt injection, SQLi, command injection via tool args), DoS, and crashes. Special attention is needed for URIs, tool arguments, prompt arguments, and any data used to interact with external systems.

5.  **Sampling (`sampling/createMessage`) - Prompt Injection & Client Resource Abuse:** Servers can provide prompt content (`messages`, `systemPrompt`) that might be used to attack the client's LLM (prompt injection). Malicious servers could also abuse the sampling feature to cause excessive cost or resource usage on the client side. Client-side user confirmation and rate limiting are essential.

6.  **Authentication & Authorization:** Securely authenticating clients and servers (especially over HTTP using OAuth 2.1/PKCE as specified) and performing granular authorization checks on the server-side for all operations (resource access, tool calls, prompt access) are fundamental.

7.  **Transport Security:** Unencrypted communication channels (HTTP, WS, potentially stdio) expose all MCP messages to eavesdropping and tampering. HTTPS/WSS must be enforced for remote connections.

8.  **Data Leakage (Logs, Errors, Responses):** Sensitive information (credentials, PII, internal system details, private data from resources/external systems) MUST NOT be leaked through log messages (`notifications/message`), error responses (`error.data`, `error.message`), or normal operation results (`tools/call` content, `resources/read` content, etc.). Requires careful sanitization and filtering at the source.

9.  **Server Interaction with External Systems:** When servers access databases, APIs, or filesystems based on MCP requests, they MUST use secure practices like parameterized queries, credential management, and least privilege to prevent downstream vulnerabilities.

10. **Client-Side Handling of Received Content:** Clients must treat content received from servers (resource `text`/`blob`, tool `content`, prompt `messages`) as potentially untrusted and handle/render it safely (e.g., sanitizing HTML/JS in resource content) to prevent XSS and other client-side attacks. 