## 4. Data Structures & Fields

This section analyzes the core data structures exchanged via MCP.

### 4.1. Capabilities

-   **Structure:** Nested objects declared during `initialize`. Top-level keys indicate features (`resources`, `tools`, `prompts`, `sampling`, `logging`, `roots`, `experimental`). Inner keys indicate sub-features (e.g., `resources: { subscribe: boolean, listChanged: boolean }`).
-   **Purpose:** Define the contract for the session.
-   **Security Considerations:**
    *   **Misinterpretation:** Ambiguity in capability definitions could lead to differing implementations and unexpected behavior.
    *   **Over-declaration:** A client/server might declare support for features it doesn't handle securely.
    *   **Granularity:** Capabilities might not be granular enough to express fine-grained permissions (e.g., allowing `resources/list` but not `resources/read` for certain resource types). Authorization ([Section 3.3](./03-protocol-interactions.md#33-authorization-http-transport)) is the primary mechanism here, but capabilities set the stage.
    *   **Experimental Features:** The `experimental` capability is inherently risky; features under it may be unstable, insecure, or change without notice. Use requires explicit opt-in and understanding of risks.

### 4.2. Resources

-   **Purpose:** Represent contextual data (files, web content, database info, etc.).
-   **Key Methods:**
    *   `resources/list`: Discover available resources (supports pagination).
    *   `resources/read`: Retrieve the content of a specific resource by URI.
    *   `resources/templates/list`: Discover parameterized resource templates (URI Templates RFC6570).
    *   `resources/subscribe`: (Optional) Client subscribes to updates for a specific resource URI.
    *   `notifications/resources/list_changed`: (Optional) Server notifies client that the list of resources has changed.
    *   `notifications/resources/updated`: (Optional) Server notifies client that a subscribed resource has changed.
-   **Resource Object:**
    *   `uri`: `string` (Unique identifier, e.g., `file:///`, `https://`, `git://`, custom schemes).
    *   `name`: `string` (Human-readable).
    *   `description`: `string` (Optional).
    *   `mimeType`: `string` (Optional, e.g., `text/plain`, `image/png`, `application/json`).
    *   `size`: `number` (Optional, bytes).
-   **Resource Content Object (in `resources/read` result):**
    *   `uri`: `string`.
    *   `mimeType`: `string`.
    *   `text`: `string` (Mutually exclusive with `blob`).
    *   `blob`: `string` (Base64 encoded binary data, mutually exclusive with `text`).
-   **Resource Template Object:**
    *   `uriTemplate`: `string` (RFC6570 URI Template).
    *   `name`: `string`.
    *   `description`: `string`.
    *   `mimeType`: `string`.
-   **Security Considerations:**
    *   **URI Handling & Path Traversal:** Servers MUST rigorously validate and sanitize incoming URIs (`resources/read`, `resources/subscribe`) to prevent path traversal attacks (e.g., `file:///../../../etc/passwd`). Canonicalize paths and enforce base directory restrictions. Custom URI schemes need equally robust validation.
    *   **Access Control:** Servers MUST check authorization *before* listing (`resources/list`) or reading (`resources/read`) resources. Sensitive resources should not be listed or readable without proper permissions.
    *   **Data Leakage:** Listing resources (`resources/list`) might inadvertently leak existence or metadata (name, description, mimeType) of sensitive files/data even if content access is restricted. Consider filtering lists based on permissions.
    *   **Large Resource DoS:** A request for a very large resource (`resources/read`) could cause DoS on the server (memory exhaustion) or client. Servers SHOULD implement size limits and potentially streaming responses (though streaming isn't explicit in the base spec). Clients should also have limits.
    *   **Subscription Storms:** Malicious clients could subscribe (`resources/subscribe`) to many resources or resources that change frequently, causing excessive notifications (`notifications/resources/updated`) and server load. Rate limiting or subscription limits are needed.
    *   **Insecure Content Handling (Client):** Clients receiving resource content (`text` or `blob`) must handle it safely based on the `mimeType`. Displaying HTML/JS content unsanitized could lead to XSS. Executing binary content is risky.
    *   **URI Template Injection:** If server-side logic constructs `uriTemplate` values based on user input without sanitization, it could lead to injection vulnerabilities allowing unintended resource access patterns. Templates themselves should be validated. Client-side expansion of templates also needs care.
    *   **Base64 Bombs:** Maliciously crafted large base64 `blob` data could cause DoS when decoded by the client or server. Implement size limits *before* decoding.
    *   **MIME Type Spoofing:** A malicious server could provide a misleading `mimeType` (e.g., `text/plain` for malicious HTML) to trick the client into unsafe handling. Clients should be cautious and potentially validate content against the claimed type.

### 4.3. Tools

-   **Purpose:** Represent functions callable by the AI model, enabling interaction with external systems.
-   **Key Methods:**
    *   `tools/list`: Discover available tools (supports pagination).
    *   `tools/call`: Invoke a specific tool by name with arguments.
    *   `notifications/tools/list_changed`: (Optional) Server notifies client that the list of tools has changed.
-   **Tool Object:**
    *   `name`: `string` (Unique identifier).
    *   `description`: `string` (Human-readable, intended for LLM).
    *   `inputSchema`: `object` (JSON Schema defining expected arguments).
    *   `annotations`: `object` (Optional, untrusted metadata about tool behavior).
-   **Tool Call Params:**
    *   `name`: `string`.
    *   `arguments`: `object` (Arguments matching the tool's `inputSchema`).
-   **Tool Call Result:**
    *   `content`: `array` (List of content items: `text`, `image`, `audio`, `resource`).
    *   `isError`: `boolean` (Indicates if the *tool execution* failed, distinct from protocol errors).
-   **Security Considerations:**
    *   **Arbitrary Code Execution Risk:** Tools fundamentally represent potential code execution on the server or interaction with external APIs. This is the highest-risk feature.
    *   **Input Validation:** Servers MUST rigorously validate `arguments` against the `inputSchema` *before* executing the tool logic. This prevents injection attacks (SQLi, command injection, etc.) within the tool implementation. Use established JSON Schema validation libraries.
    *   **Access Control:** Servers MUST check if the client (and underlying user) is authorized to call the specific tool (`tools/call`) and potentially with the given arguments.
    *   **Output Sanitization:** Tool results (`content`) returned to the client MUST be sanitized, especially `text` content. If results include user-generated or external API data, it could contain malicious scripts (XSS) if rendered directly by the client/host UI. Base64 `blob` data for images/audio also needs size validation. Embedded `resource` content inherits resource security considerations.
    *   **Untrusted Descriptions/Annotations:** Clients/Hosts MUST treat `description` and `annotations` as potentially misleading, especially if the server isn't fully trusted. The LLM might be tricked into calling a harmful tool based on a false description. User confirmation is critical.
    *   **Data Exfiltration via Arguments:** The LLM (prompted by a malicious user or compromised) could attempt to exfiltrate sensitive data available in its context by placing it into the `arguments` of a `tools/call`. Clients/Hosts SHOULD review arguments before sending or implement data loss prevention (DLP).
    *   **Tool Chaining Attacks:** Complex interactions involving multiple tool calls could lead to unexpected states or vulnerabilities.
    *   **Denial of Service:** Malicious clients could call tools repeatedly (`tools/call`) or provide arguments causing excessive computation or external API calls. Rate limiting per-user/per-client/per-tool is essential.
    *   **Error Reporting:** Tool execution errors (`isError: true`) should not leak sensitive internal details in the returned `content`.

### 4.4. Prompts

-   **Purpose:** Provide structured, templated messages/instructions, often user-initiated (e.g., slash commands).
-   **Key Methods:**
    *   `prompts/list`: Discover available prompts (supports pagination).
    *   `prompts/get`: Retrieve a specific prompt's content, optionally providing arguments for customization.
    *   `notifications/prompts/list_changed`: (Optional) Server notifies client that the list of prompts has changed.
-   **Prompt Object:**
    *   `name`: `string` (Unique identifier).
    *   `description`: `string` (Optional, human-readable).
    *   `arguments`: `array` (Optional, list of argument definitions: `name`, `description`, `required`).
-   **Prompt Get Params:**
    *   `name`: `string`.
    *   `arguments`: `object` (Optional, values for defined arguments).
-   **Prompt Get Result:**
    *   `description`: `string`.
    *   `messages`: `array` (List of `PromptMessage` objects).
-   **PromptMessage Object:**
    *   `role`: `string` (`user` or `assistant`).
    *   `content`: `object` (Can be `text`, `image`, `audio`, or `resource`). Content structure matches tool results/resource contents.
-   **Security Considerations:**
    *   **Argument Injection:** If the server generates the `messages` in the `prompts/get` response by inserting provided `arguments` into templates without proper sanitization, it could lead to injection attacks (e.g., injecting control characters, prompt injection payloads within arguments). Servers MUST sanitize arguments before using them in templates.
    *   **Access Control:** Servers should ensure the client is authorized to list (`prompts/list`) or get (`prompts/get`) specific prompts, especially if prompts could expose sensitive information or workflows.
    *   **Data Exposure in Prompts:** Prompt templates themselves or the results of `prompts/get` (after argument insertion) might contain sensitive information if not designed carefully.
    *   **Misleading Prompts:** Similar to tool descriptions, a malicious server could provide prompts (`description` or `messages`) designed to trick the user or LLM into unsafe actions.
    *   **Resource Handling:** Embedded `resource` content within prompt messages inherits all security considerations from [Section 4.2](./04-data-structures.md#42-resources). Servers must ensure arguments don't lead to unauthorized resource embedding. Clients must handle received resources safely.
    *   **Complexity/DoS:** Very complex prompts or prompts requiring extensive server-side processing based on arguments could lead to DoS.

### 4.5. Sampling (Client Feature)

-   **Purpose:** Allows Servers to request LLM generation (completion) from the Client/Host.
-   **Capability:** Client declares `sampling: {}`.
-   **Key Method:**
    *   `sampling/createMessage` (Server -> Client Request): Requests the client to generate a message using its LLM.
-   **Request Params (`sampling/createMessage`):**
    *   `messages`: `array` (List of `PromptMessage` objects, similar to `prompts/get` result, forming the context/prompt).
    *   `modelPreferences`: `object` (Optional hints for model selection: `hints` (array of `{name: string}`), `costPriority`, `speedPriority`, `intelligencePriority` (all 0-1)).
    *   `systemPrompt`: `string` (Optional).
    *   `maxTokens`: `number` (Optional).
-   **Result (`sampling/createMessage`):**
    *   `role`: `string` (Usually `assistant`).
    *   `content`: `object` (The generated content: `text`, `image`, `audio`).
    *   `model`: `string` (Identifier of the model used by the client).
    *   `stopReason`: `string` (Reason generation stopped, e.g., `endTurn`, `maxTokens`).
-   **Security Considerations:**
    *   **User Consent & Control (CRITICAL):** As the spec *strongly recommends*, Clients MUST implement robust user confirmation before sending the request to the LLM and potentially before returning the response to the Server. Users should be able to view/edit the prompt.
    *   **Prompt Injection from Server:** The `messages` and `systemPrompt` provided by the Server could contain malicious instructions intended to manipulate the Client's LLM or exfiltrate data from the Client's context if the Client blindly concatenates them with other data before sending to the LLM.
    *   **Resource Consumption (Client-Side):** Malicious Servers could send frequent or computationally expensive `sampling/createMessage` requests, causing high LLM costs or resource usage on the Client side. Clients MUST implement rate limiting and potentially cost controls.
    *   **Data Leakage in Prompts:** Sensitive information from the Server's context could be included in the `messages` sent to the Client. While the Client controls LLM access, this data is still exposed to the Client application and potentially the user.
    *   **Data Leakage in Responses:** The LLM's response (`content`) might contain sensitive information (either hallucinated or derived from sensitive training data) which is then sent back to the Server. Clients might need to filter/review responses.
    *   **Model Selection Manipulation:** A malicious Server might use `modelPreferences` to try and force the Client to use a less secure or less capable model, although the Client has final control.
    *   **Content Validation:** Both Client and Server should validate the content (`text`, `image`, `audio`) received to prevent attacks (e.g., Base64 bombs, malicious media files).

### 4.6. Roots (Client Feature)

-   **Purpose:** Allows Clients to inform Servers about the accessible filesystem root directories (workspaces, projects).
-   **Capability:** Client declares `roots: { listChanged: boolean }`.
-   **Key Methods:**
    *   `roots/list` (Server -> Client Request): Server asks the Client for the list of roots.
    *   `notifications/roots/list_changed`: (Optional) Client notifies Server that the list of roots has changed.
-   **Root Object:**
    *   `uri`: `string` (MUST be a `file://` URI).
    *   `name`: `string` (Optional, human-readable).
-   **Security Considerations:**
    *   **Information Disclosure:** Exposing root URIs (`roots/list`) reveals filesystem structure information to the Server. Clients MUST ensure only intended roots are exposed, ideally with user consent per root.
    *   **Insecure Root Exposure:** Clients MUST NOT expose sensitive directories (e.g., `/`, `C:\`, system folders, user profile root) unless explicitly intended and understood by the user.
    *   **URI Validation (Client):** Clients MUST validate the URIs they expose to ensure they are well-formed `file://` URIs and correspond to actual, intended locations. Path traversal issues are less likely here (as the client *provides* the roots) but validation is still good practice.
    *   **Server Misuse of Roots:** Servers receive the root list as information. They MUST respect these boundaries when constructing resource URIs (e.g., for `resources/read`). A malicious Server might ignore the roots and try to access files outside them (`file:///etc/passwd`), relying on the Server's *own* access control for resources (see [Section 4.2](./04-data-structures.md#42-resources)) to prevent this. The `roots` mechanism itself is primarily informational for the server.
    *   **Race Conditions:** If roots change (`notifications/roots/list_changed`) while a Server is performing operations based on the old list, inconsistencies could occur. Servers need to handle updates gracefully.

### 4.7. Utility Features

Summarizes miscellaneous protocol utilities and their security aspects.

-   **Pagination (`resources/list`, `tools/list`, `prompts/list`, etc.):**
    *   Mechanism: Opaque `cursor` in request params, `nextCursor` in results.
    *   Security: Cursors MUST be treated as opaque by clients. Servers MUST validate received cursors to prevent unauthorized access to data or information disclosure if cursors encode state/permissions insecurely. Servers should ensure cursors expire or are session-bound.
-   **Cancellation (`notifications/cancelled`):**
    *   Mechanism: Notification sent by request initiator with `requestId` to cancel.
    *   Security: Primarily a functional concern. Malicious cancellation floods could cause minor DoS. Receivers MUST validate that the `requestId` corresponds to an active request they received to prevent cross-request interference (though the impact is likely low).
-   **Progress (`notifications/progress`):**
    *   Mechanism: Request includes `_meta: { progressToken: ... }`. Receiver sends notifications with token and progress values (`progress`, `total`, `message`).
    *   Security: `progressToken` uniqueness must be enforced by the *sender* of the original request. Receivers should validate tokens correspond to active requests. Sensitive information MUST NOT be leaked in the `message` field of the progress notification. Progress notification floods could cause minor DoS.
-   **Ping (`ping` request):**
    *   Mechanism: Simple request/response to check liveness.
    *   Security: Minimal risk. Potential for minor DoS via ping floods if not rate-limited (though less likely to be effective than other methods). Primarily used for connection health.
-   **Logging (`notifications/message`, `logging/setLevel` request):**
    *   Mechanism: Server sends log notifications (`level`, `logger`, `data`). Client can optionally set minimum `level`.
    *   Security (CRITICAL): Log data (`params.data`) MUST NOT contain sensitive information (credentials, PII, internal system details). Servers MUST sanitize logs before sending. Clients should be careful about displaying raw log data that might contain control characters or other harmful content. Log flooding could cause DoS on the client.
-   **Completion (`completion/complete` request):**
    *   Mechanism: Client requests suggestions for prompt/resource arguments (`ref`, `argument` { `name`, `value` }). Server responds with suggestions (`values`, `total`, `hasMore`).
    *   Security: Server MUST validate `ref` and `argument.name` to ensure client is authorized to get completions for that item/argument. Suggestions (`values`) returned by the server MUST NOT leak sensitive information (e.g., suggesting private filenames, user data). Server should rate-limit completion requests. Clients should sanitize suggestions before display.