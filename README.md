# img-src MCP Server

Model Context Protocol (MCP) server for [img-src.io](https://img-src.io) image hosting API.

This server enables AI assistants like Claude to interact with your img-src.io account - uploading, searching, listing, and managing images directly through natural language.

## Installation

```bash
pnpm add -g @img-src/mcp-server
```

Or run directly with pnpm dlx:

```bash
pnpm dlx @img-src/mcp-server
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `IMG_SRC_API_KEY` | Yes | Your img-src.io API key (starts with `imgsrc_`) |
| `IMG_SRC_API_URL` | No | API base URL (default: `https://api.img-src.io`) |

### Getting an API Key

1. Log in to [img-src.io](https://img-src.io)
2. Go to Settings > API Keys
3. Create a new API key
4. Copy the key (it starts with `imgsrc_`)

## Usage with Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "img-src": {
      "command": "npx",
      "args": ["@img-src/mcp-server"],
      "env": {
        "IMG_SRC_API_KEY": "imgsrc_your_api_key_here"
      }
    }
  }
}
```

## Available Tools

### upload_image

Upload an image from a local file or URL to your img-src.io account.

```
Upload ~/Photos/sunset.jpg to img-src as photos/vacation/sunset.jpg
```

**Parameters:**
- `url` (optional): URL of the image to upload
- `data` (optional): Base64-encoded image data (for local file uploads)
- `mimeType` (optional): MIME type of the image (required when using `data`)
- `target_path` (optional): Target path for organizing the image

Note: Either `url` or `data` must be provided.

### list_images

List images in your account, optionally within a specific folder.

```
List my img-src images in the photos/vacation folder
```

**Parameters:**
- `folder` (optional): Folder path to list
- `limit` (optional): Max items to return (default: 50)
- `offset` (optional): Items to skip for pagination

### search_images

Search for images by filename or path.

```
Search for img-src images containing "beach"
```

**Parameters:**
- `query` (required): Search query
- `limit` (optional): Max results (default: 20)
- `offset` (optional): Results to skip

### get_image

Get detailed metadata for a specific image.

```
Get details for my img-src image at photos/vacation/sunset.jpg
```

**Parameters:**
- `id` (required): Image ID (UUID) or filepath

### delete_image

Permanently delete an image.

```
Delete my img-src image at photos/old/unused.jpg
```

**Parameters:**
- `id` (required): Image ID (UUID) or filepath to delete

### get_usage

View your current usage statistics.

```
Show my img-src usage stats
```

### get_settings

Get your account settings and configuration.

```
What are my img-src account settings?
```

### get_cdn_url

Generate a CDN URL with optional image transformations.

```
Generate an img-src CDN URL for john/photos/beach.jpg resized to 800x600
```

**Parameters:**
- `username` (required): Image owner's username
- `filepath` (required): Image path
- `width` (optional): Resize width
- `height` (optional): Resize height
- `fit` (optional): cover, contain, fill, scale-down
- `quality` (optional): 1-100 (default: 80)
- `format` (optional): webp, avif, jpeg, png

## Resources

The MCP server exposes your images as resources that Claude can access directly:

- **URI format**: `imgsrc://images/{imageId}`
- **Content**: JSON metadata including dimensions, formats, and CDN URLs

Claude can list and read these resources to understand what images you have and their properties.

## Prompts

Pre-built prompts for common workflows:

### upload-and-share
Upload an image and get shareable CDN URLs.
- Arguments: `imageUrl` (required), `width` (optional)

### check-usage
Check account usage and storage status.
- No arguments required

### find-images
Search for images by keyword.
- Arguments: `query` (required)

## Example Conversations

### Upload and share an image

> User: Upload ~/Photos/sunset.jpg to img-src and give me a resized URL

> Claude: I'll upload that image and generate a CDN URL for you.
>
> [Uses upload_image tool]
>
> Image uploaded successfully! Here's a resized CDN URL:
> https://img-src.io/i/yourname/sunset.webp?w=1200&q=85

### Search and organize

> User: Find all my beach photos

> Claude: [Uses search_images with query "beach"]
>
> Found 5 beach photos:
> 1. photos/vacation/beach-sunset.jpg
> 2. photos/summer/beach-party.png
> ...

### Check usage

> User: How much storage am I using?

> Claude: [Uses get_usage tool]
>
> Your img-src.io usage:
> - Storage: 245 MB / 500 MB (49%)
> - Uploads: 67 / 100 this month
> - Bandwidth: 1.2 GB / 1 GB (120% - consider upgrading!)

## Development

```bash
# Install dependencies
pnpm install

# Build
pnpm build

# Run locally
IMG_SRC_API_KEY=imgsrc_xxx pnpm start

# Type check
pnpm type-check

# Run tests
pnpm test
```

## License

MIT
