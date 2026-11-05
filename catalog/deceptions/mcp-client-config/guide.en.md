## Story

Place the configuration of an MCP client where developers keep their tools. Developers connect AI assistants to internal servers over the Model Context Protocol, and the configuration holds the address and the key of the server. The file `mcp.json` configures a server named `knowledge-base` that is reached over HTTP, with an `Authorization` header and a random token. The host name of the server belongs to a DNS honeytoken: a client that connects to the server looks up the name, which raises an event. No server stands behind the name, and the token exists nowhere.

## Setup

1. Create the DNS honeytoken "MCP server". Replace `Honeytoken-Domain` in the file with its name.
2. Place the file as `.mcp.json` in the root of a project directory that developers use, or as `mcp.json` in the configuration directory of the AI assistant that you pretend.
3. Do not place it in a project that somebody opens with an assistant. The client would ask to approve the server, and an approval would let it connect.
4. Record in the notes of the scenario where you placed the file.

## Testing

On a computer with access to the internet, run `nslookup Honeytoken-Domain`, with the name of the honeytoken, or `curl https://Honeytoken-Domain/mcp`. Within a minute, the scenario shows an incident. Close the incident after the test.

If no incident appears, check that the computer resolves names through a resolver that reaches the DNS role of Nyktus, see Limits.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- Clients ask before they connect to a server from the configuration of a project. The file raises an event only where somebody has approved the server or uses the URL. Reading the file raises none.
- The host name is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
