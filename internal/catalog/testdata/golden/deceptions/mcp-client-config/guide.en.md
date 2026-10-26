# Configuration of an MCP client

Developers connect AI assistants to internal servers over the Model Context Protocol, and the configuration holds the address and the key of the server. The file below tells this story.

## Configuration of an MCP client

The file `mcp.json` configures an MCP server named `knowledge-base` that is reached over HTTP: the URL `https://mcpq3xwz7a2kfm4ub6tyc5nre.d.example.net/mcp` and an `Authorization` header with a random token. The host name belongs to a DNS honeytoken: a client that connects to the server resolves it, which raises an event. No server stands behind it, and the token exists nowhere.

### Placing the file

1. Place the file as `.mcp.json` in the root of a project directory that developers use, or as `mcp.json` in the configuration directory of the AI assistant that you pretend.
2. Do not place it in a project that somebody opens with an assistant: the client would ask to approve the server, and an approval would let it connect.
3. Record where you placed it in the placement notes of the artifact.

### Testing

Resolve the host with `nslookup mcpq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet, or run `curl https://mcpq3xwz7a2kfm4ub6tyc5nre.d.example.net/mcp`. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- Clients ask before they connect to a server from the configuration of a project, and the file raises an event only where somebody has approved the server or uses the URL. Reading the file raises none.
- The host name is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
