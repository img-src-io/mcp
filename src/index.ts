#!/usr/bin/env node

/**
 * img-src.io MCP Server
 *
 * Provides Model Context Protocol tools for interacting with the img-src.io
 * image hosting and CDN API. Enables AI models to upload, list, search,
 * and manage images programmatically.
 *
 * Environment Variables:
 *   IMG_SRC_API_KEY - Required. API key with 'imgsrc_' prefix
 *   IMG_SRC_API_URL - Optional. API base URL (default: https://api.img-src.io)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

// =============================================================================
// Configuration
// =============================================================================

const API_URL = process.env.IMG_SRC_API_URL ?? "https://api.img-src.io";
const API_KEY = process.env.IMG_SRC_API_KEY;
const API_TIMEOUT_MS = 30000; // 30 seconds
const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB

// =============================================================================
// Utilities
// =============================================================================

/**
 * Sanitize filepath to prevent path traversal attacks
 */
function sanitizePath(path: string): string {
  // Decode URL-encoded characters first to catch encoded path traversal
  let decoded = path;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    // Keep original if decoding fails (e.g., invalid encoding)
  }

  return decoded
    .replace(/\.\.\//g, "") // Remove ../
    .replace(/\.\.\\/g, "") // Remove ..\
    .replace(/^\/+/, ""); // Remove leading slashes
}

// =============================================================================
// API Client
// =============================================================================

interface ApiError {
  code: string;
  message: string;
  status: number;
}

interface ApiResponse<T> {
  data?: T;
  error?: ApiError;
}

async function apiRequest<T>(
  method: string,
  path: string,
  body?: unknown,
  isFormData = false
): Promise<ApiResponse<T>> {
  if (!API_KEY) {
    return {
      error: {
        code: "MISSING_API_KEY",
        message:
          "IMG_SRC_API_KEY environment variable is not set. Please set it to your img-src.io API key.",
        status: 401,
      },
    };
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${API_KEY}`,
  };

  if (!isFormData && body) {
    headers["Content-Type"] = "application/json";
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, API_TIMEOUT_MS);

  try {
    const response = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      body: isFormData ? (body as FormData) : body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    let data: { error?: { code?: string; message?: string } };
    try {
      data = (await response.json()) as { error?: { code?: string; message?: string } };
    } catch (parseError) {
      return {
        error: {
          code: "JSON_PARSE_ERROR",
          message: `Failed to parse API response: ${parseError instanceof Error ? parseError.message : "Invalid JSON"}`,
          status: response.status,
        },
      };
    }

    if (!response.ok) {
      return {
        error: {
          code: data.error?.code ?? "API_ERROR",
          message: data.error?.message ?? `API request failed with status ${String(response.status)}`,
          status: response.status,
        },
      };
    }

    return { data: data as T };
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "AbortError") {
      return {
        error: {
          code: "TIMEOUT",
          message: `Request timed out after ${String(API_TIMEOUT_MS / 1000)} seconds`,
          status: 0,
        },
      };
    }
    const message = err instanceof Error ? err.message : "Unknown error occurred";
    return {
      error: {
        code: "NETWORK_ERROR",
        message: `Failed to connect to img-src.io API: ${message}`,
        status: 0,
      },
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

// =============================================================================
// Type Definitions (matching api/openapi.json)
// =============================================================================

// GET /api/v1/images/:id response
interface MetadataResponse {
  id: string;
  metadata: {
    hash: string;
    original_filename: string;
    size: number;
    uploaded_at: string;
    mime_type: string;
    width?: number;
    height?: number;
    dominant_color?: string;
  };
  urls: {
    original: string;
    webp: string;
    avif: string;
    jpeg: string;
    png: string;
  };
  visibility: "public" | "private";
  _links: {
    self: string;
    delete: string;
  };
}

// GET /api/v1/images response item
interface ImageListItem {
  id: string;
  original_filename: string;
  sanitized_filename?: string;
  size: number;
  uploaded_at: string;
  url: string;
  cdn_url?: string;
  paths: string[];
  visibility: "public" | "private";
  active_signed_url?: {
    signed_url: string;
    expires_at: number;
  };
}

interface FolderItem {
  name: string;
  image_count: number;
}

interface ImageListResponse {
  images: ImageListItem[];
  folders: FolderItem[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
  path_filter?: string;
}

// GET /api/v1/images/search response item
interface SearchResult {
  id: string;
  original_filename: string;
  sanitized_filename?: string;
  paths: string[];
  size: number;
  uploaded_at: string;
  url: string;
  cdn_url?: string;
  visibility: "public" | "private";
}

interface SearchResponse {
  results: SearchResult[];
  total: number;
  query: string;
}

// POST /api/v1/images response
interface UploadResponse {
  id: string;
  hash: string;
  url: string;
  paths: string[];
  is_new?: boolean;
  size: number;
  format: string;
  dimensions?: {
    width: number;
    height: number;
  };
  available_formats: {
    webp: string;
    avif: string;
    jpeg: string;
  };
  uploaded_at: string;
  visibility: "public" | "private";
  _links: {
    self: string;
    delete: string;
  };
}

// GET /api/v1/usage response
interface UsageResponse {
  plan: string;
  plan_name: string;
  plan_status: "active" | "cancelling" | "expired";
  subscription_ends_at: number | null;
  plan_limits: {
    max_uploads_per_month: number | null;
    max_storage_bytes: number | null;
    max_bandwidth_per_month: number | null;
    max_api_requests_per_month: number | null;
    max_transformations_per_month: number | null;
  };
  total_images: number;
  storage_used_bytes: number;
  storage_used_mb: number;
  storage_used_gb: number;
  current_period: {
    period: string;
    period_start: number;
    period_end: number;
    uploads: number;
    bandwidth_bytes: number;
    api_requests: number;
    transformations: number;
  };
  credits: {
    storage_bytes: number;
    api_requests: number;
    transformations: number;
  };
}

interface SettingsResponse {
  settings: {
    id: string;
    username: string;
    email?: string;
    plan: string;
    delivery_formats: string[];
    default_quality: number;
    default_fit_mode: string;
    default_max_width?: number;
    default_max_height?: number;
    theme: string;
    language: string;
    created_at: number;
    updated_at: number;
    total_uploads: number;
    storage_used_bytes: number;
  };
}

// DELETE /api/v1/images/:id response
interface DeleteResponse {
  success: boolean;
  message: string;
  deleted_paths?: string[];
  deleted_at: string;
}

// =============================================================================
// Zod Schemas for Tool Arguments
// =============================================================================

const UploadImageArgsSchema = z
  .object({
    url: z.url("Invalid URL format").optional(),
    data: z.string().optional(),
    mimeType: z.string().optional(),
    filepath: z.string().optional(),
  })
  .refine((d) => d.url ?? d.data, {
    message: "Either url or data is required",
  })
  .refine((d) => !d.data || d.mimeType, {
    message: "mimeType is required when using data",
  });

const ListImagesArgsSchema = z.object({
  folder: z.string().optional(),
  limit: z.number().int().min(1).max(100).optional(),
  offset: z.number().int().min(0).optional(),
});

const SearchImagesArgsSchema = z.object({
  query: z.string().min(1, "Search query is required"),
  limit: z.number().int().min(1).max(100).optional(),
  offset: z.number().int().min(0).optional(),
});

const GetImageArgsSchema = z.object({
  id: z.string().min(1, "Image ID is required"),
});

const DeleteImageArgsSchema = z.object({
  id: z.string().min(1, "Image ID is required"),
});

const GetCdnUrlArgsSchema = z.object({
  username: z.string().min(1, "Username is required"),
  filepath: z.string().min(1, "Filepath is required"),
  width: z.number().int().positive().optional(),
  height: z.number().int().positive().optional(),
  fit: z.enum(["cover", "contain", "fill", "scale-down"]).optional(),
  quality: z.number().int().min(1).max(100).optional(),
  format: z.enum(["webp", "avif", "jpeg", "png"]).optional(),
});

// =============================================================================
// Tool Definitions
// =============================================================================

const tools: Tool[] = [
  {
    name: "upload_image",
    description:
      "Upload an image to img-src.io from URL or base64 data. Supports JPEG, PNG, WebP, GIF, AVIF, HEIC, and more. " +
      "Images are automatically deduplicated by content hash. " +
      "Returns the image metadata including CDN URLs for different formats.",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "URL of the image to upload. The image will be fetched and uploaded.",
        },
        data: {
          type: "string",
          description: "Base64-encoded image data. Use this for local file uploads.",
        },
        mimeType: {
          type: "string",
          description:
            "MIME type of the image (e.g., 'image/png', 'image/jpeg'). Required when using data parameter.",
        },
        filepath: {
          type: "string",
          description:
            "Optional path to store the image (e.g., 'photos/vacation/beach.jpg'). " +
            "If not provided, the original filename from the URL will be used.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_images",
    description:
      "List images in your img-src.io account. " +
      "Supports pagination and folder browsing. " +
      "Returns images and subfolders in the specified path.",
    inputSchema: {
      type: "object" as const,
      properties: {
        folder: {
          type: "string",
          description:
            "Folder path to list (e.g., 'photos/vacation'). " +
            "Leave empty to list root folder.",
        },
        limit: {
          type: "number",
          description: "Maximum number of items to return (default: 50, max: 100).",
        },
        offset: {
          type: "number",
          description: "Number of items to skip for pagination (default: 0).",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "search_images",
    description:
      "Search for images by filename or path. " +
      "Performs a fuzzy search across all your images. " +
      "Returns matching images with their metadata and CDN URLs.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query to match against filenames and paths.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return (default: 20, max: 100).",
        },
        offset: {
          type: "number",
          description: "Number of results to skip for pagination (default: 0).",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
  },
  {
    name: "get_image",
    description:
      "Get detailed metadata for a specific image by its ID. " +
      "Returns full image information including dimensions, format, " +
      "all associated paths, and CDN URLs.",
    inputSchema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "The image ID (UUID format).",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "delete_image",
    description:
      "Delete an image by its ID. " +
      "This permanently removes the image and all its paths from your account. " +
      "The image will no longer be accessible via CDN URLs.",
    inputSchema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "The image ID (UUID format) to delete.",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "get_usage",
    description:
      "Get current usage statistics for your img-src.io account. " +
      "Shows uploads, storage, bandwidth, and API request usage " +
      "against your plan limits.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "get_settings",
    description:
      "Get your img-src.io account settings. " +
      "Returns username, plan, default image settings, " +
      "and account statistics.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "get_cdn_url",
    description:
      "Generate a CDN URL for an image with optional transformations. " +
      "Supports resizing, format conversion, and quality adjustment.",
    inputSchema: {
      type: "object" as const,
      properties: {
        username: {
          type: "string",
          description: "The username who owns the image.",
        },
        filepath: {
          type: "string",
          description: "The image filepath (e.g., 'photos/beach.jpg').",
        },
        width: {
          type: "number",
          description: "Resize width in pixels.",
        },
        height: {
          type: "number",
          description: "Resize height in pixels.",
        },
        fit: {
          type: "string",
          enum: ["cover", "contain", "fill", "scale-down"],
          description: "How to fit the image within the dimensions (default: contain).",
        },
        quality: {
          type: "number",
          description: "Image quality 1-100 (default: 80).",
        },
        format: {
          type: "string",
          enum: ["webp", "avif", "jpeg", "png"],
          description: "Output format. WebP is recommended for best compression.",
        },
      },
      required: ["username", "filepath"],
      additionalProperties: false,
    },
  },
];

// =============================================================================
// Tool Handlers
// =============================================================================

async function handleUploadImage(args: {
  url?: string;
  data?: string;
  mimeType?: string;
  filepath?: string;
}): Promise<string> {
  // Sanitize filepath if provided
  const sanitizedFilepath = args.filepath ? sanitizePath(args.filepath) : undefined;

  let imageBlob: Blob;
  let filename: string;

  if (args.data) {
    // Handle base64 data upload
    try {
      const binaryData = Buffer.from(args.data, "base64");
      imageBlob = new Blob([binaryData], { type: args.mimeType ?? "application/octet-stream" });
    } catch {
      return JSON.stringify({
        error: {
          code: "INVALID_BASE64",
          message: "Failed to decode base64 data",
        },
      });
    }

    // Determine filename from filepath or generate one
    if (sanitizedFilepath) {
      filename = sanitizedFilepath.split("/").pop() ?? "image";
    } else {
      // Generate filename from mime type
      const ext = args.mimeType?.split("/")[1] ?? "bin";
      filename = `image.${ext}`;
    }
  } else if (args.url) {
    // Fetch the image from the URL with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, API_TIMEOUT_MS);

    let imageResponse: Response;
    try {
      imageResponse = await fetch(args.url, { signal: controller.signal });
      if (!imageResponse.ok) {
        return JSON.stringify({
          error: {
            code: "FETCH_FAILED",
            message: `Failed to fetch image from URL: ${String(imageResponse.status)} ${imageResponse.statusText}`,
          },
        });
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") {
        return JSON.stringify({
          error: {
            code: "TIMEOUT",
            message: `Image fetch timed out after ${String(API_TIMEOUT_MS / 1000)} seconds`,
          },
        });
      }
      const message = err instanceof Error ? err.message : "Unknown error";
      return JSON.stringify({
        error: {
          code: "FETCH_ERROR",
          message: `Failed to fetch image from URL: ${message}`,
        },
      });
    } finally {
      clearTimeout(timeoutId);
    }

    imageBlob = await imageResponse.blob();

    // Determine filename from URL or filepath
    if (sanitizedFilepath) {
      filename = sanitizedFilepath.split("/").pop() ?? "image";
    } else {
      const urlPath = new URL(args.url).pathname;
      filename = urlPath.split("/").pop() ?? "image";
    }
  } else {
    return JSON.stringify({
      error: {
        code: "MISSING_INPUT",
        message: "Either url or data is required",
      },
    });
  }

  // Check image size before upload
  if (imageBlob.size > MAX_IMAGE_SIZE) {
    return JSON.stringify({
      error: {
        code: "IMAGE_TOO_LARGE",
        message: `Image size (${(imageBlob.size / (1024 * 1024)).toFixed(2)} MB) exceeds 5 MB limit`,
      },
    });
  }

  // Create form data for upload
  const formData = new FormData();
  formData.append("file", imageBlob, filename);
  if (sanitizedFilepath) {
    formData.append("filepath", sanitizedFilepath);
  }

  const result = await apiRequest<UploadResponse>("POST", "/api/v1/images", formData, true);

  if (result.error) {
    return JSON.stringify({ error: result.error });
  }

  return JSON.stringify({
    success: true,
    image: result.data,
    message:
      result.data?.is_new === false
        ? "Image uploaded (deduplicated - identical content already existed)"
        : "Image uploaded successfully",
  });
}

async function handleListImages(args: {
  folder?: string;
  limit?: number;
  offset?: number;
}): Promise<string> {
  const params = new URLSearchParams();
  if (args.folder) params.set("folder", args.folder);
  if (args.limit) params.set("limit", String(args.limit));
  if (args.offset) params.set("offset", String(args.offset));

  const queryString = params.toString();
  const path = `/api/v1/images${queryString ? `?${queryString}` : ""}`;

  const result = await apiRequest<ImageListResponse>("GET", path);

  if (result.error) {
    return JSON.stringify({ error: result.error });
  }

  return JSON.stringify({
    success: true,
    ...result.data,
  });
}

async function handleSearchImages(args: {
  query: string;
  limit?: number;
  offset?: number;
}): Promise<string> {
  const params = new URLSearchParams();
  params.set("q", args.query);
  if (args.limit) params.set("limit", String(args.limit));
  if (args.offset) params.set("offset", String(args.offset));

  const result = await apiRequest<SearchResponse>("GET", `/api/v1/images/search?${params.toString()}`);

  if (result.error) {
    return JSON.stringify({ error: result.error });
  }

  return JSON.stringify({
    success: true,
    ...result.data,
  });
}

async function handleGetImage(args: { id: string }): Promise<string> {
  const result = await apiRequest<MetadataResponse>("GET", `/api/v1/images/${args.id}`);

  if (result.error) {
    return JSON.stringify({ error: result.error });
  }

  const data = result.data;
  return JSON.stringify({
    success: true,
    id: data?.id,
    metadata: data?.metadata,
    urls: data?.urls,
    visibility: data?.visibility,
    _links: data?._links,
  });
}

async function handleDeleteImage(args: { id: string }): Promise<string> {
  const result = await apiRequest<DeleteResponse>("DELETE", `/api/v1/images/${args.id}`);

  if (result.error) {
    return JSON.stringify({ error: result.error });
  }

  return JSON.stringify({
    success: true,
    ...result.data,
    message: "Image deleted successfully",
  });
}

async function handleGetUsage(): Promise<string> {
  const result = await apiRequest<UsageResponse>("GET", "/api/v1/usage");

  if (result.error) {
    return JSON.stringify({ error: result.error });
  }

  const data = result.data;
  const limits = data?.plan_limits;
  const period = data?.current_period;

  const formatUsage = (used: number, limit: number | null, unit: string) => {
    if (limit === null) return `${used.toLocaleString()} ${unit} (unlimited)`;
    const percentage = ((used / limit) * 100).toFixed(1);
    return `${used.toLocaleString()} / ${limit.toLocaleString()} ${unit} (${percentage}%)`;
  };

  const formatBytes = (bytes: number): string => {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${String(bytes)} bytes`;
  };

  return JSON.stringify({
    success: true,
    plan: data?.plan,
    plan_name: data?.plan_name,
    plan_status: data?.plan_status,
    current_period: {
      period: period?.period,
      start: period?.period_start,
      end: period?.period_end,
    },
    usage: {
      uploads: formatUsage(
        period?.uploads ?? 0,
        limits?.max_uploads_per_month ?? null,
        "uploads"
      ),
      storage: `${formatBytes(data?.storage_used_bytes ?? 0)} used` +
        (limits?.max_storage_bytes
          ? ` / ${formatBytes(limits.max_storage_bytes)} (${(((data?.storage_used_bytes ?? 0) / limits.max_storage_bytes) * 100).toFixed(1)}%)`
          : " (unlimited)"),
      bandwidth: formatUsage(
        period?.bandwidth_bytes ?? 0,
        limits?.max_bandwidth_per_month ?? null,
        `bytes (${formatBytes(period?.bandwidth_bytes ?? 0)})`
      ),
      api_requests: formatUsage(
        period?.api_requests ?? 0,
        limits?.max_api_requests_per_month ?? null,
        "requests"
      ),
      transformations: formatUsage(
        period?.transformations ?? 0,
        limits?.max_transformations_per_month ?? null,
        "transformations"
      ),
    },
    total_images: data?.total_images,
    credits: data?.credits,
  });
}

async function handleGetSettings(): Promise<string> {
  const result = await apiRequest<SettingsResponse>("GET", "/api/v1/settings");

  if (result.error) {
    return JSON.stringify({ error: result.error });
  }

  return JSON.stringify({
    success: true,
    settings: result.data?.settings,
  });
}

function handleGetCdnUrl(args: {
  username: string;
  filepath: string;
  width?: number;
  height?: number;
  fit?: string;
  quality?: number;
  format?: string;
}): string {
  // Sanitize inputs
  const sanitizedFilepath = sanitizePath(args.filepath);
  const sanitizedUsername = args.username.replace(/[^a-zA-Z0-9_-]/g, "");

  // Validate username is not empty after sanitization
  if (!sanitizedUsername) {
    return JSON.stringify({
      error: {
        code: "INVALID_USERNAME",
        message: "Username is empty after sanitization",
      },
    });
  }

  // Build the CDN URL with transformation parameters
  // Handle complex extensions like .tar.gz by only replacing the last extension
  const lastDotIndex = sanitizedFilepath.lastIndexOf(".");
  const basePath = lastDotIndex > 0 ? sanitizedFilepath.slice(0, lastDotIndex) : sanitizedFilepath;
  const extension = args.format ?? "webp";

  const params = new URLSearchParams();
  if (args.width) params.set("w", String(args.width));
  if (args.height) params.set("h", String(args.height));
  if (args.fit) params.set("fit", args.fit);
  if (args.quality) params.set("q", String(args.quality));

  const queryString = params.toString();
  const url = `https://img-src.io/i/${sanitizedUsername}/${basePath}.${extension}${queryString ? `?${queryString}` : ""}`;

  return JSON.stringify({
    success: true,
    url,
    parameters: {
      username: sanitizedUsername,
      filepath: sanitizedFilepath,
      width: args.width,
      height: args.height,
      fit: args.fit ?? "contain",
      quality: args.quality ?? 80,
      format: extension,
    },
  });
}

// =============================================================================
// Server Setup
// =============================================================================

async function main() {
  const server = new Server(
    {
      name: "img-src-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
    }
  );

  // Handle tool listing
  server.setRequestHandler(ListToolsRequestSchema, () => {
    return { tools };
  });

  // Handle tool execution
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      let result: string;

      switch (name) {
        case "upload_image": {
          const parsed = UploadImageArgsSchema.safeParse(args);
          if (!parsed.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify({
                    error: { code: "INVALID_ARGS", message: parsed.error.message },
                  }),
                },
              ],
              isError: true,
            };
          }
          result = await handleUploadImage(parsed.data);
          break;
        }

        case "list_images": {
          const parsed = ListImagesArgsSchema.safeParse(args);
          if (!parsed.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify({
                    error: { code: "INVALID_ARGS", message: parsed.error.message },
                  }),
                },
              ],
              isError: true,
            };
          }
          result = await handleListImages(parsed.data);
          break;
        }

        case "search_images": {
          const parsed = SearchImagesArgsSchema.safeParse(args);
          if (!parsed.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify({
                    error: { code: "INVALID_ARGS", message: parsed.error.message },
                  }),
                },
              ],
              isError: true,
            };
          }
          result = await handleSearchImages(parsed.data);
          break;
        }

        case "get_image": {
          const parsed = GetImageArgsSchema.safeParse(args);
          if (!parsed.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify({
                    error: { code: "INVALID_ARGS", message: parsed.error.message },
                  }),
                },
              ],
              isError: true,
            };
          }
          result = await handleGetImage(parsed.data);
          break;
        }

        case "delete_image": {
          const parsed = DeleteImageArgsSchema.safeParse(args);
          if (!parsed.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify({
                    error: { code: "INVALID_ARGS", message: parsed.error.message },
                  }),
                },
              ],
              isError: true,
            };
          }
          result = await handleDeleteImage(parsed.data);
          break;
        }

        case "get_usage":
          result = await handleGetUsage();
          break;

        case "get_settings":
          result = await handleGetSettings();
          break;

        case "get_cdn_url": {
          const parsed = GetCdnUrlArgsSchema.safeParse(args);
          if (!parsed.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify({
                    error: { code: "INVALID_ARGS", message: parsed.error.message },
                  }),
                },
              ],
              isError: true,
            };
          }
          result = handleGetCdnUrl(parsed.data);
          break;
        }

        default:
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: { code: "UNKNOWN_TOOL", message: `Unknown tool: ${name}` },
                }),
              },
            ],
            isError: true,
          };
      }

      // Check if result contains an error and set isError flag accordingly
      const parsedResult = JSON.parse(result) as { error?: unknown };
      const hasError = "error" in parsedResult;

      return {
        content: [
          {
            type: "text" as const,
            text: result,
          },
        ],
        ...(hasError && { isError: true }),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error occurred";
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ error: { code: "INTERNAL_ERROR", message } }),
          },
        ],
        isError: true,
      };
    }
  });

  // =============================================================================
  // Resources Handlers
  // =============================================================================

  // List available resources (images)
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    const result = await apiRequest<ImageListResponse>("GET", "/api/v1/images?limit=100");
    if (result.error) {
      return { resources: [] };
    }

    return {
      resources: result.data!.images.map((img) => ({
        uri: `imgsrc://images/${img.id}`,
        name: img.original_filename,
        mimeType: "image/*",
        description: `Image: ${img.paths.join(", ")}`,
      })),
    };
  });

  // Read a specific resource
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;
    const match = /^imgsrc:\/\/images\/(.+)$/.exec(uri);
    if (!match) {
      return { contents: [] };
    }

    const imageId = match[1];
    const result = await apiRequest<MetadataResponse>("GET", `/api/v1/images/${imageId}`);

    if (result.error) {
      return { contents: [] };
    }

    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(result.data, null, 2),
        },
      ],
    };
  });

  // =============================================================================
  // Prompts Handlers
  // =============================================================================

  const prompts = [
    {
      name: "upload-and-share",
      description: "Upload an image and get shareable CDN URLs",
      arguments: [
        { name: "imageUrl", description: "URL of image to upload", required: true },
        { name: "width", description: "Resize width (optional)", required: false },
      ],
    },
    {
      name: "check-usage",
      description: "Check account usage and storage status",
    },
    {
      name: "find-images",
      description: "Search for images by keyword",
      arguments: [{ name: "query", description: "Search keyword", required: true }],
    },
  ];

  // List available prompts
  server.setRequestHandler(ListPromptsRequestSchema, () => {
    return { prompts };
  });

  // Get a specific prompt
  server.setRequestHandler(GetPromptRequestSchema, (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "upload-and-share":
        return {
          messages: [
            {
              role: "user" as const,
              content: {
                type: "text" as const,
                text: `Upload this image: ${args?.imageUrl ?? "[image URL]"}${args?.width ? ` and resize to ${args.width}px width` : ""}. Then give me the CDN URL.`,
              },
            },
          ],
        };
      case "check-usage":
        return {
          messages: [
            {
              role: "user" as const,
              content: {
                type: "text" as const,
                text: "Check my img-src.io usage stats and let me know if I'm close to any limits.",
              },
            },
          ],
        };
      case "find-images":
        return {
          messages: [
            {
              role: "user" as const,
              content: {
                type: "text" as const,
                text: `Find all my images matching "${args?.query ?? "[keyword]"}" and show me the results.`,
              },
            },
          ],
        };
      default:
        throw new Error(`Unknown prompt: ${name}`);
    }
  });

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Log to stderr so it doesn't interfere with MCP protocol on stdout
  console.error("img-src MCP server started");
}

main().catch((err: unknown) => {
  console.error("Failed to start MCP server:", err);
  process.exit(1);
});
