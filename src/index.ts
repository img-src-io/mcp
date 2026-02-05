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

import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFile, stat } from "node:fs/promises";
import { resolve, extname, basename } from "node:path";
import { z } from "zod";

// =============================================================================
// Image File Utilities
// =============================================================================

/**
 * Allowed image extensions and their MIME types
 */
const IMAGE_MIME_TYPES: Record<string, string> = {
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".bmp": "image/bmp",
  ".tiff": "image/tiff",
  ".tif": "image/tiff",
  ".ico": "image/x-icon",
  ".svg": "image/svg+xml",
  ".heic": "image/heic",
  ".heif": "image/heif",
};

/**
 * Get MIME type from file extension
 */
function getMimeTypeFromPath(filePath: string): string | null {
  const ext = extname(filePath).toLowerCase();
  return IMAGE_MIME_TYPES[ext] ?? null;
}

/**
 * Check if file path is a valid image file
 */
function isAllowedImagePath(filePath: string): { allowed: boolean; reason?: string } {
  const ext = extname(filePath).toLowerCase();

  if (!ext) {
    return { allowed: false, reason: "File has no extension" };
  }

  if (!IMAGE_MIME_TYPES[ext]) {
    return { allowed: false, reason: `Extension '${ext}' is not a supported image format` };
  }

  return { allowed: true };
}

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
 * Check if a URL is safe to fetch (SSRF protection)
 * Blocks internal networks, localhost, and cloud metadata endpoints
 */
function isAllowedUrl(urlString: string): { allowed: boolean; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { allowed: false, reason: "Invalid URL format" };
  }

  // Only allow http and https protocols
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { allowed: false, reason: `Protocol '${parsed.protocol}' is not allowed` };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block localhost variants
  const localhostPatterns = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
  ];
  if (localhostPatterns.includes(hostname)) {
    return { allowed: false, reason: "Localhost URLs are not allowed" };
  }

  // Block cloud metadata endpoints
  const metadataEndpoints = [
    "169.254.169.254", // AWS, GCP, Azure metadata
    "metadata.google.internal",
    "metadata.goog",
  ];
  if (metadataEndpoints.includes(hostname)) {
    return { allowed: false, reason: "Cloud metadata endpoints are not allowed" };
  }

  // Block private IP ranges (RFC 1918)
  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (ipv4Match) {
    const [, a, b] = ipv4Match.map(Number);
    // 10.0.0.0/8
    if (a === 10) {
      return { allowed: false, reason: "Private network URLs are not allowed" };
    }
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) {
      return { allowed: false, reason: "Private network URLs are not allowed" };
    }
    // 192.168.0.0/16
    if (a === 192 && b === 168) {
      return { allowed: false, reason: "Private network URLs are not allowed" };
    }
    // 169.254.0.0/16 (link-local)
    if (a === 169 && b === 254) {
      return { allowed: false, reason: "Link-local URLs are not allowed" };
    }
  }

  return { allowed: true };
}

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

  // Split path into segments, filter out dangerous ones, rejoin
  // This completely removes ".." segments regardless of nesting
  return decoded
    .split(/[/\\]+/)
    .filter((segment) => segment !== ".." && segment !== "." && segment !== "")
    .join("/");
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
    file_path: z
      .string()
      .optional()
      .describe("PREFERRED: Absolute path to local image file (e.g., /Users/name/photo.png). Use this instead of base64 data."),
    url: z
      .url("Invalid URL format")
      .optional()
      .describe("URL of image to download and upload (for web images)"),
    data: z
      .string()
      .optional()
      .describe("Base64-encoded image data. AVOID: causes context length issues. Use file_path instead."),
    mimeType: z
      .string()
      .optional()
      .describe("MIME type (required only when using data, e.g., image/png)"),
    target_path: z
      .string()
      .optional()
      .describe("Optional: Folder path to store the image (e.g., 'photos/2024'). Filename is determined from source."),
  })
  .refine((d) => d.file_path ?? d.url ?? d.data, {
    message: "One of file_path, url, or data is required",
  })
  .refine((d) => !d.data || d.mimeType, {
    message: "mimeType is required when using data",
  });

const ListImagesArgsSchema = z.object({
  folder: z
    .string()
    .optional()
    .describe("Folder path to filter images (e.g., 'blog/2024'). Omit to list root level."),
  limit: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .describe("Max images to return (1-100, default: 50)"),
  offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("Number of images to skip for pagination (default: 0)"),
});

const SearchImagesArgsSchema = z.object({
  query: z
    .string()
    .min(1)
    .max(100)
    .describe("Search term to match against filenames and paths (1-100 chars)"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .describe("Max results to return (1-100, default: 20)"),
  offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("Number of results to skip for pagination (default: 0)"),
});

const GetImageArgsSchema = z.object({
  id: z
    .string()
    .length(16)
    .describe("Image ID (16-character hash prefix, e.g., 'abcdef1234567890')"),
});

const DeleteImageArgsSchema = z.object({
  id: z
    .string()
    .length(16)
    .describe("Image ID to delete (16-character hash prefix). This permanently removes the image and all its paths."),
});

const GetCdnUrlArgsSchema = z.object({
  username: z
    .string()
    .min(1)
    .describe("img-src.io username (appears in CDN URL path)"),
  filepath: z
    .string()
    .min(1)
    .describe("Image path without extension (e.g., 'blog/photo' for blog/photo.webp)"),
  width: z
    .number()
    .int()
    .positive()
    .optional()
    .describe("Resize width in pixels"),
  height: z
    .number()
    .int()
    .positive()
    .optional()
    .describe("Resize height in pixels"),
  fit: z
    .enum(["cover", "contain", "fill", "scale-down"])
    .optional()
    .describe("Resize fit mode: cover (crop), contain (fit), fill (stretch), scale-down (shrink only)"),
  quality: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .describe("Image quality 1-100 (default: 80)"),
  format: z
    .enum(["webp", "avif", "jpeg", "png"])
    .optional()
    .describe("Output format (default: webp)"),
});


// =============================================================================
// Tool Handlers
// =============================================================================

async function handleUploadImage(args: {
  file_path?: string;
  url?: string;
  data?: string;
  mimeType?: string;
  target_path?: string;
}): Promise<string> {
  // Sanitize target_path if provided
  const sanitizedFilepath = args.target_path ? sanitizePath(args.target_path) : undefined;

  let imageBlob: Blob;
  let filename: string;

  if (args.file_path) {
    // Handle local file upload
    const pathCheck = isAllowedImagePath(args.file_path);
    if (!pathCheck.allowed) {
      return JSON.stringify({
        error: {
          code: "INVALID_FILE_TYPE",
          message: pathCheck.reason ?? "File type not allowed",
        },
      });
    }

    // Resolve to absolute path
    const absolutePath = resolve(args.file_path);

    // Check file exists and get size
    let fileStats;
    try {
      fileStats = await stat(absolutePath);
    } catch {
      return JSON.stringify({
        error: {
          code: "FILE_NOT_FOUND",
          message: `File not found: ${args.file_path}`,
        },
      });
    }

    if (!fileStats.isFile()) {
      return JSON.stringify({
        error: {
          code: "NOT_A_FILE",
          message: `Path is not a file: ${args.file_path}`,
        },
      });
    }

    // Check file size before reading
    if (fileStats.size > MAX_IMAGE_SIZE) {
      return JSON.stringify({
        error: {
          code: "IMAGE_TOO_LARGE",
          message: `Image size (${(fileStats.size / (1024 * 1024)).toFixed(2)} MB) exceeds 5 MB limit`,
        },
      });
    }

    // Read file as binary
    const fileBuffer = await readFile(absolutePath);
    const mimeType = getMimeTypeFromPath(absolutePath) ?? "application/octet-stream";
    imageBlob = new Blob([fileBuffer], { type: mimeType });

    // Determine filename from target_path or original file name
    if (sanitizedFilepath) {
      filename = sanitizedFilepath.split("/").pop() ?? basename(absolutePath);
    } else {
      filename = basename(absolutePath);
    }
  } else if (args.data) {
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

    // Determine filename from target_path or generate one
    if (sanitizedFilepath) {
      filename = sanitizedFilepath.split("/").pop() ?? "image";
    } else {
      // Generate filename from mime type
      const ext = args.mimeType?.split("/")[1] ?? "bin";
      filename = `image.${ext}`;
    }
  } else if (args.url) {
    // Validate URL before fetching (SSRF protection)
    const urlCheck = isAllowedUrl(args.url);
    if (!urlCheck.allowed) {
      return JSON.stringify({
        error: {
          code: "FORBIDDEN_URL",
          message: `URL not allowed: ${urlCheck.reason ?? "Unknown reason"}`,
        },
      });
    }

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

    // Determine filename from URL or target_path
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
        message: "One of file_path, url, or data is required",
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
    formData.append("target_path", sanitizedFilepath);
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

/**
 * Helper to wrap tool handler result as CallToolResult
 */
function wrapToolResult(result: string): { content: { type: "text"; text: string }[]; isError?: boolean } {
  const parsedResult = JSON.parse(result) as { error?: unknown };
  const hasError = "error" in parsedResult;

  return {
    content: [{ type: "text", text: result }],
    ...(hasError && { isError: true }),
  };
}

async function main() {
  const server = new McpServer(
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

  // =============================================================================
  // Tool Registrations
  // =============================================================================

  server.registerTool(
    "upload_image",
    {
      description:
        "Upload an image to img-src.io. " +
        "IMPORTANT: Always prefer 'file_path' (absolute path like /Users/name/image.png) over base64 'data' to avoid context length limits. " +
        "Use 'url' for web images. Only use 'data' as last resort for small images. " +
        "Supports JPEG, PNG, WebP, GIF, AVIF, HEIC, and more. Max 5MB. " +
        "Returns CDN URLs for the uploaded image.",
      inputSchema: UploadImageArgsSchema,
    },
    async (args) => wrapToolResult(await handleUploadImage(args))
  );

  server.registerTool(
    "list_images",
    {
      description:
        "List images in your img-src.io account. " +
        "Supports pagination and folder browsing. " +
        "Returns images and subfolders in the specified path.",
      inputSchema: ListImagesArgsSchema,
    },
    async (args) => wrapToolResult(await handleListImages(args))
  );

  server.registerTool(
    "search_images",
    {
      description:
        "Search for images by filename or path. " +
        "Performs a fuzzy search across all your images. " +
        "Returns matching images with their metadata and CDN URLs.",
      inputSchema: SearchImagesArgsSchema,
    },
    async (args) => wrapToolResult(await handleSearchImages(args))
  );

  server.registerTool(
    "get_image",
    {
      description:
        "Get detailed metadata for a specific image by its ID. " +
        "Returns full image information including dimensions, format, " +
        "all associated paths, and CDN URLs.",
      inputSchema: GetImageArgsSchema,
    },
    async (args) => wrapToolResult(await handleGetImage(args))
  );

  server.registerTool(
    "delete_image",
    {
      description:
        "Delete an image by its ID. " +
        "This permanently removes the image and all its paths from your account. " +
        "The image will no longer be accessible via CDN URLs.",
      inputSchema: DeleteImageArgsSchema,
    },
    async (args) => wrapToolResult(await handleDeleteImage(args))
  );

  server.registerTool(
    "get_usage",
    {
      description:
        "Get current usage statistics for your img-src.io account. " +
        "Shows uploads, storage, bandwidth, and API request usage " +
        "against your plan limits.",
    },
    async () => wrapToolResult(await handleGetUsage())
  );

  server.registerTool(
    "get_settings",
    {
      description:
        "Get your img-src.io account settings. " +
        "Returns username, plan, default image settings, " +
        "and account statistics.",
    },
    async () => wrapToolResult(await handleGetSettings())
  );

  server.registerTool(
    "get_cdn_url",
    {
      description:
        "Generate a CDN URL for an image with optional transformations. " +
        "Supports resizing, format conversion, and quality adjustment.",
      inputSchema: GetCdnUrlArgsSchema,
    },
    (args) => wrapToolResult(handleGetCdnUrl(args))
  );

  // =============================================================================
  // Resource Registration
  // =============================================================================

  server.registerResource(
    "images",
    new ResourceTemplate("imgsrc://images/{imageId}", {
      list: async () => {
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
      },
    }),
    {
      description: "Image resources from your img-src.io account",
      mimeType: "application/json",
    },
    async (uri, variables) => {
      const imageId = variables.imageId as string;
      const result = await apiRequest<MetadataResponse>("GET", `/api/v1/images/${imageId}`);

      if (result.error) {
        return { contents: [] };
      }

      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify(result.data, null, 2),
          },
        ],
      };
    }
  );

  // =============================================================================
  // Prompt Registrations
  // =============================================================================

  server.registerPrompt(
    "upload-and-share",
    {
      description: "Upload an image and get shareable CDN URLs",
      argsSchema: {
        imageUrl: z.string().describe("URL of image to upload"),
        width: z.string().optional().describe("Resize width (optional)"),
      },
    },
    (args) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `Upload this image: ${args.imageUrl}${args.width ? ` and resize to ${args.width}px width` : ""}. Then give me the CDN URL.`,
          },
        },
      ],
    })
  );

  server.registerPrompt(
    "check-usage",
    {
      description: "Check account usage and storage status",
    },
    () => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: "Check my img-src.io usage stats and let me know if I'm close to any limits.",
          },
        },
      ],
    })
  );

  server.registerPrompt(
    "find-images",
    {
      description: "Search for images by keyword",
      argsSchema: {
        query: z.string().describe("Search keyword"),
      },
    },
    (args) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `Find all my images matching "${args.query}" and show me the results.`,
          },
        },
      ],
    })
  );

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
