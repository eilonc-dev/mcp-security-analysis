## 2. Core Concepts (Based on Specification `2025-03-26`)

MCP facilitates integration between LLM applications and external data sources/tools using JSON-RPC 2.0.

### 2.1. Roles

-   **Host:** The LLM application initiating connections (e.g., IDE, Chat Interface).
-   **Client:** Connectors within the Host application, managing communication with specific Servers. *Note: Often the Host acts as the Client.*
-   **Server:** Services providing context, tools, or capabilities to the Host/Client.

### 2.2. Communication Foundation

-   **Protocol:** JSON-RPC 2.0 over a suitable transport (e.g., WebSockets, stdio).
-   **State:** Connections are stateful.
-   **Capabilities:** Server and Client capabilities are negotiated during initialization.

### 2.3. Key Features Provided by Servers

Servers can offer one or more of the following features:

-   **Resources:** Contextual data for user or AI model consumption (e.g., files, database entries, web content).
-   **Prompts:** Templated messages or predefined workflows presented to the user.
-   **Tools:** Functions callable by the AI model, potentially executing code or interacting with external systems.

### 2.4. Key Features Provided by Clients

Clients may offer the following feature to Servers:

-   **Sampling:** Server-initiated requests for the Host/Client to perform LLM interactions (potentially recursive).

### 2.5. Additional Utilities

The protocol includes support for:

-   Configuration management
-   Progress tracking for long-running operations
-   Request cancellation
-   Standardized error reporting
-   Logging

### 2.6. Stated Security Principles (from Specification)

The specification explicitly calls out the need for implementors to address security and trust, emphasizing:

-   **User Consent and Control:** Explicit user understanding and approval for data access and actions. Clear UI/UX for authorization.
-   **Data Privacy:** Explicit consent before exposing user data; protection of data.
-   **Tool Safety:** Treat tools as arbitrary code execution paths. Verify descriptions. Explicit user consent before invocation.
-   **LLM Sampling Controls:** Explicit user approval for sampling requests, control over prompts and result visibility.

**Note:** The specification states MCP *cannot enforce* these principles at the protocol level and relies on implementors (`Host`, `Client`, `Server`) to build robust consent, authorization, and protection mechanisms. 