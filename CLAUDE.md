# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

This is the **@img-src/mcp-server** — an MCP (Model Context Protocol) server that enables AI assistants to interact with the img-src.io image processing API programmatically.

## Commands

```bash
pnpm install          # Install dependencies
pnpm build            # Build TypeScript to dist/
pnpm start            # Start MCP server (stdio transport)
pnpm test             # Run tests with Vitest
pnpm type-check       # TypeScript type checking
pnpm lint             # ESLint
```

### CI Checks (what PR builds run)

```bash
pnpm build && pnpm lint && pnpm type-check && pnpm test
```

CI matrix: Node.js 20, 22 on ubuntu-latest.

## Architecture

### Single-file Structure

```
src/
├── index.ts          # Main MCP server implementation
└── index.test.ts     # Tests
```

### Key Dependencies

- `@modelcontextprotocol/sdk` — MCP SDK for server implementation
- `zod` — Runtime schema validation

### Available Tools

| Tool | Description |
|------|-------------|
| `upload_image` | Upload image from local file or URL |
| `list_images` | List images in folder with pagination |
| `search_images` | Search by filename/path |
| `get_image` | Get image metadata by ID |
| `delete_image` | Delete an image |
| `get_usage` | View usage statistics |
| `get_settings` | Get account settings |
| `get_cdn_url` | Generate CDN URL with transformations |

### Configuration

The server requires `IMG_SRC_API_KEY` environment variable:

```json
{
  "mcpServers": {
    "img-src": {
      "command": "npx",
      "args": ["@img-src/mcp-server"],
      "env": {
        "IMG_SRC_API_KEY": "imgsrc_your_api_key"
      }
    }
  }
}
```

## Testing

Uses **Vitest** for testing. Tests mock the MCP SDK and HTTP requests.

```bash
pnpm test                    # Run all tests
pnpm test -- --watch         # Watch mode
```

## CD/Publishing

The server is published to npm automatically when a git tag is pushed.

### Release Process

```bash
# 1. Update version in package.json
# 2. Commit the version bump
# 3. Tag and push to trigger publish
git tag v1.0.0
git push origin v1.0.0
```

### Publish Workflow (`.github/workflows/publish.yml`)

1. Runs full test suite across Node.js 20, 22
2. Validates git tag matches `package.json` version (fails if mismatch)
3. Publishes to npm with `--provenance` flag (supply chain security)
4. Creates a GitHub Release with auto-generated notes

**Requirements:**
- `NPM_TOKEN` secret in GitHub repository settings
- Tag format: `v*` (e.g., `v1.0.0`)
- Tag version must match `package.json` version exactly

**Permissions:** `contents: write` (GitHub releases), `id-token: write` (npm provenance)

## Supported Runtimes

Node.js 20+. Uses stdio transport for MCP communication.
