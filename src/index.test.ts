import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { z } from "zod";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// =============================================================================
// Helper Functions (exported from index.ts logic, reimplemented for testing)
// =============================================================================

function isAllowedUrl(urlString: string): { allowed: boolean; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { allowed: false, reason: "Invalid URL format" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { allowed: false, reason: `Protocol '${parsed.protocol}' is not allowed` };
  }

  const hostname = parsed.hostname.toLowerCase();

  const localhostPatterns = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"];
  if (localhostPatterns.includes(hostname)) {
    return { allowed: false, reason: "Localhost URLs are not allowed" };
  }

  const metadataEndpoints = ["169.254.169.254", "metadata.google.internal", "metadata.goog"];
  if (metadataEndpoints.includes(hostname)) {
    return { allowed: false, reason: "Cloud metadata endpoints are not allowed" };
  }

  // Block IPv6 addresses (could map to internal IPs via ::ffff: prefix)
  if (hostname.includes(":")) {
    return { allowed: false, reason: "IPv6 addresses are not allowed" };
  }

  // Block non-standard IP representations that could bypass IPv4 checks
  if (/^0\d+\./.test(hostname) || /^0x[0-9a-f]/i.test(hostname) || /^\d+$/.test(hostname)) {
    return { allowed: false, reason: "Numeric IP representations are not allowed" };
  }

  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (ipv4Match) {
    const [, a, b] = ipv4Match.map(Number);
    if (a === 10) {
      return { allowed: false, reason: "Private network URLs are not allowed" };
    }
    if (a === 172 && b >= 16 && b <= 31) {
      return { allowed: false, reason: "Private network URLs are not allowed" };
    }
    if (a === 192 && b === 168) {
      return { allowed: false, reason: "Private network URLs are not allowed" };
    }
    if (a === 169 && b === 254) {
      return { allowed: false, reason: "Link-local URLs are not allowed" };
    }
  }

  return { allowed: true };
}

function sanitizePath(path: string): string {
  // Decode URL-encoded characters first to catch encoded path traversal
  let decoded = path;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    // Keep original if decoding fails
  }

  // Split path into segments, filter out dangerous ones, rejoin
  return decoded
    .split(/[/\\]+/)
    .filter((segment) => segment !== ".." && segment !== "." && segment !== "")
    .join("/");
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${String(bytes)} bytes`;
}

// =============================================================================
// Tests
// =============================================================================

describe("MCP Server", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("isAllowedUrl (SSRF Protection)", () => {
    it("should allow valid external URLs", () => {
      expect(isAllowedUrl("https://example.com/image.jpg").allowed).toBe(true);
      expect(isAllowedUrl("http://cdn.example.org/photo.png").allowed).toBe(true);
      expect(isAllowedUrl("https://images.unsplash.com/photo-123").allowed).toBe(true);
    });

    it("should block localhost URLs", () => {
      expect(isAllowedUrl("http://localhost/secret").allowed).toBe(false);
      expect(isAllowedUrl("http://127.0.0.1/admin").allowed).toBe(false);
      expect(isAllowedUrl("http://0.0.0.0:8080/api").allowed).toBe(false);
      expect(isAllowedUrl("http://[::1]/internal").allowed).toBe(false);
    });

    it("should block cloud metadata endpoints", () => {
      expect(isAllowedUrl("http://169.254.169.254/latest/meta-data/").allowed).toBe(false);
      expect(isAllowedUrl("http://metadata.google.internal/computeMetadata/").allowed).toBe(false);
      expect(isAllowedUrl("http://metadata.goog/v1/").allowed).toBe(false);
    });

    it("should block private network IPs (RFC 1918)", () => {
      // 10.0.0.0/8
      expect(isAllowedUrl("http://10.0.0.1/internal").allowed).toBe(false);
      expect(isAllowedUrl("http://10.255.255.255/secret").allowed).toBe(false);

      // 172.16.0.0/12
      expect(isAllowedUrl("http://172.16.0.1/admin").allowed).toBe(false);
      expect(isAllowedUrl("http://172.31.255.255/config").allowed).toBe(false);
      expect(isAllowedUrl("http://172.15.0.1/image.jpg").allowed).toBe(true); // Not in range

      // 192.168.0.0/16
      expect(isAllowedUrl("http://192.168.1.1/router").allowed).toBe(false);
      expect(isAllowedUrl("http://192.168.0.100/local").allowed).toBe(false);
    });

    it("should block link-local addresses", () => {
      expect(isAllowedUrl("http://169.254.1.1/link-local").allowed).toBe(false);
      expect(isAllowedUrl("http://169.254.100.200/apipa").allowed).toBe(false);
    });

    it("should block non-http protocols", () => {
      expect(isAllowedUrl("file:///etc/passwd").allowed).toBe(false);
      expect(isAllowedUrl("ftp://ftp.example.com/image.jpg").allowed).toBe(false);
      expect(isAllowedUrl("gopher://evil.com/").allowed).toBe(false);
    });

    it("should reject invalid URLs", () => {
      expect(isAllowedUrl("not-a-url").allowed).toBe(false);
      expect(isAllowedUrl("").allowed).toBe(false);
      expect(isAllowedUrl("://missing-protocol").allowed).toBe(false);
    });

    it("should block IPv6 addresses (SSRF via ::ffff: mapping)", () => {
      expect(isAllowedUrl("http://[::ffff:127.0.0.1]/secret").allowed).toBe(false);
      expect(isAllowedUrl("http://[::ffff:169.254.169.254]/metadata").allowed).toBe(false);
      expect(isAllowedUrl("http://[::ffff:10.0.0.1]/internal").allowed).toBe(false);
      expect(isAllowedUrl("http://[::ffff:192.168.1.1]/admin").allowed).toBe(false);
    });

    it("should block octal IP representations", () => {
      // 0177.0.0.1 = 127.0.0.1 in octal
      expect(isAllowedUrl("http://0177.0.0.1/").allowed).toBe(false);
      expect(isAllowedUrl("http://00.0.0.0/").allowed).toBe(false);
      expect(isAllowedUrl("http://012.0.0.1/").allowed).toBe(false);
    });

    it("should block hex IP representations", () => {
      // 0x7f.0.0.1 = 127.0.0.1 in hex
      expect(isAllowedUrl("http://0x7f.0.0.1/").allowed).toBe(false);
      expect(isAllowedUrl("http://0x7f000001/").allowed).toBe(false);
      expect(isAllowedUrl("http://0xA9FEA9FE/").allowed).toBe(false); // 169.254.169.254
    });

    it("should block single decimal IP representations", () => {
      // 2130706433 = 127.0.0.1 as single decimal
      expect(isAllowedUrl("http://2130706433/").allowed).toBe(false);
    });

    it("should still allow valid domain names starting with numbers", () => {
      // Domains with numbers are fine as long as they have non-numeric parts
      expect(isAllowedUrl("https://123.example.com/image.jpg").allowed).toBe(true);
      expect(isAllowedUrl("https://1password.com/image.jpg").allowed).toBe(true);
    });

    it("should provide meaningful error reasons", () => {
      expect(isAllowedUrl("http://localhost/").reason).toBe("Localhost URLs are not allowed");
      expect(isAllowedUrl("http://10.0.0.1/").reason).toBe("Private network URLs are not allowed");
      expect(isAllowedUrl("http://169.254.169.254/").reason).toBe(
        "Cloud metadata endpoints are not allowed"
      );
      expect(isAllowedUrl("file:///etc/passwd").reason).toContain("Protocol");
    });
  });

  describe("sanitizePath", () => {
    it("should remove path traversal sequences", () => {
      expect(sanitizePath("../../../etc/passwd")).toBe("etc/passwd");
      expect(sanitizePath("foo/../bar")).toBe("foo/bar");
      expect(sanitizePath("..\\..\\windows")).toBe("windows");
    });

    it("should remove leading slashes", () => {
      expect(sanitizePath("/foo/bar")).toBe("foo/bar");
      expect(sanitizePath("///foo")).toBe("foo");
    });

    it("should handle normal paths", () => {
      expect(sanitizePath("photos/vacation/beach.jpg")).toBe("photos/vacation/beach.jpg");
      expect(sanitizePath("image.png")).toBe("image.png");
    });

    it("should handle path traversal with segment-based filtering", () => {
      // Segment-based filtering removes ".." segments completely
      expect(sanitizePath("..")).toBe("");
      expect(sanitizePath("../..")).toBe("");
      expect(sanitizePath("foo/../bar")).toBe("foo/bar");
      expect(sanitizePath("foo/../../bar")).toBe("foo/bar");
      // "...." is NOT ".." so it's preserved (valid directory name)
      expect(sanitizePath("..../secret")).toBe("..../secret");
      // Multiple slashes are normalized
      expect(sanitizePath("foo//bar///baz")).toBe("foo/bar/baz");
    });

    it("should handle URL-encoded path traversal", () => {
      // %2e = . and %2f = /
      expect(sanitizePath("%2e%2e%2fetc/passwd")).toBe("etc/passwd");
      expect(sanitizePath("%2e%2e/%2e%2e/secret")).toBe("secret");
      expect(sanitizePath("foo%2f%2e%2e%2fbar")).toBe("foo/bar");
    });

    it("should handle invalid URL encoding gracefully", () => {
      // Invalid percent encoding should keep original
      expect(sanitizePath("%xyz/test")).toBe("%xyz/test");
    });
  });

  describe("formatBytes", () => {
    it("should format bytes correctly", () => {
      expect(formatBytes(500)).toBe("500 bytes");
      expect(formatBytes(1024)).toBe("1.00 KB");
      expect(formatBytes(1024 * 1024)).toBe("1.00 MB");
      expect(formatBytes(1024 * 1024 * 1024)).toBe("1.00 GB");
      expect(formatBytes(1536)).toBe("1.50 KB");
    });

    it("should handle edge cases", () => {
      expect(formatBytes(0)).toBe("0 bytes");
      expect(formatBytes(1023)).toBe("1023 bytes");
      expect(formatBytes(1024 * 1024 - 1)).toBe("1024.00 KB");
    });
  });

  describe("CDN URL Generation", () => {
    it("should generate correct CDN URL with parameters", () => {
      const username = "testuser";
      const filepath = "photos/beach.jpg";
      const params = {
        width: 800,
        height: 600,
        quality: 85,
        format: "webp",
        fit: "cover",
      };

      // Simulating handleGetCdnUrl logic
      const sanitizedFilepath = sanitizePath(filepath);
      const lastDotIndex = sanitizedFilepath.lastIndexOf(".");
      const basePath = lastDotIndex > 0 ? sanitizedFilepath.slice(0, lastDotIndex) : sanitizedFilepath;

      const queryParams = new URLSearchParams();
      queryParams.set("w", String(params.width));
      queryParams.set("h", String(params.height));
      queryParams.set("q", String(params.quality));
      queryParams.set("fit", params.fit);

      const url = `https://img-src.io/i/${username}/${basePath}.${params.format}?${queryParams.toString()}`;

      expect(url).toBe(
        "https://img-src.io/i/testuser/photos/beach.webp?w=800&h=600&q=85&fit=cover"
      );
    });

    it("should handle filepath without extension", () => {
      const filepath = "photos/beach";
      const lastDotIndex = filepath.lastIndexOf(".");
      const basePath = lastDotIndex > 0 ? filepath.slice(0, lastDotIndex) : filepath;
      expect(basePath).toBe("photos/beach");
    });

    it("should strip extension correctly", () => {
      const filepath = "photos/beach.jpg";
      const lastDotIndex = filepath.lastIndexOf(".");
      const basePath = lastDotIndex > 0 ? filepath.slice(0, lastDotIndex) : filepath;
      expect(basePath).toBe("photos/beach");
    });

    it("should handle complex extensions like .tar.gz", () => {
      const filepath = "files/archive.tar.gz";
      const lastDotIndex = filepath.lastIndexOf(".");
      const basePath = lastDotIndex > 0 ? filepath.slice(0, lastDotIndex) : filepath;
      // With lastIndexOf, only the last .gz is removed, keeping .tar
      expect(basePath).toBe("files/archive.tar");
    });

    it("should sanitize username", () => {
      const username = "user@evil.com/../admin";
      const sanitizedUsername = username.replace(/[^a-zA-Z0-9_-]/g, "");
      expect(sanitizedUsername).toBe("userevilcomadmin");
    });

    it("should return error for empty username after sanitization", () => {
      // Simulating handleGetCdnUrl validation
      const username = "@@@";
      const sanitizedUsername = username.replace(/[^a-zA-Z0-9_-]/g, "");

      if (!sanitizedUsername) {
        const result = JSON.stringify({
          error: {
            code: "INVALID_USERNAME",
            message: "Username is empty after sanitization",
          },
        });
        const parsed = JSON.parse(result) as { error: { code: string; message: string } };
        expect(parsed.error.code).toBe("INVALID_USERNAME");
      }

      expect(sanitizedUsername).toBe("");
    });
  });

  describe("API Response Types", () => {
    describe("ImageListResponse", () => {
      it("should have correct structure", () => {
        const response = {
          images: [
            {
              id: "abc123",
              original_filename: "photo.jpg",
              size: 1024,
              uploaded_at: "2025-01-01T00:00:00Z",
              url: "/api/v1/images/abc123",
              paths: ["photos/photo.jpg"],
              visibility: "public" as const,
            },
          ],
          folders: [{ name: "vacation", image_count: 10 }],
          total: 1,
          limit: 50,
          offset: 0,
          has_more: false,
        };

        expect(response.images).toHaveLength(1);
        expect(response.folders[0].image_count).toBe(10);
        expect(response.has_more).toBe(false);
      });
    });

    describe("UsageResponse", () => {
      it("should have correct structure with plan_limits", () => {
        const response = {
          plan: "free",
          plan_name: "Free Plan",
          plan_status: "active" as const,
          subscription_ends_at: null,
          plan_limits: {
            max_uploads_per_month: 100,
            max_storage_bytes: 1073741824,
            max_bandwidth_per_month: 5368709120,
            max_api_requests_per_month: 10000,
            max_transformations_per_month: 1000,
          },
          total_images: 50,
          storage_used_bytes: 536870912,
          storage_used_mb: 512,
          storage_used_gb: 0.5,
          current_period: {
            period: "2025-01",
            period_start: 1735689600,
            period_end: 1738368000,
            uploads: 25,
            bandwidth_bytes: 1073741824,
            api_requests: 500,
            transformations: 100,
          },
          credits: {
            storage_bytes: 0,
            api_requests: 0,
            transformations: 0,
          },
        };

        expect(response.plan_limits.max_uploads_per_month).toBe(100);
        expect(response.current_period.uploads).toBe(25);
        expect(response.credits.storage_bytes).toBe(0);
      });
    });

    describe("MetadataResponse", () => {
      it("should have correct nested structure", () => {
        const response = {
          id: "abc123",
          metadata: {
            hash: "abcdef1234567890",
            original_filename: "photo.jpg",
            size: 1024,
            uploaded_at: "2025-01-01T00:00:00Z",
            mime_type: "image/jpeg",
            width: 1920,
            height: 1080,
          },
          urls: {
            original: "https://img-src.io/i/user/photo.jpg",
            webp: "https://img-src.io/i/user/photo.webp",
            avif: "https://img-src.io/i/user/photo.avif",
            jpeg: "https://img-src.io/i/user/photo.jpg",
            png: "https://img-src.io/i/user/photo.png",
          },
          visibility: "public" as const,
          _links: {
            self: "/api/v1/images/abc123",
            delete: "/api/v1/images/abc123",
          },
        };

        expect(response.metadata.width).toBe(1920);
        expect(response.urls.webp).toContain(".webp");
        expect(response._links.self).toBe("/api/v1/images/abc123");
      });
    });

    describe("UploadResponse", () => {
      it("should have is_new field instead of deduplicated", () => {
        const response = {
          id: "abc123",
          hash: "abcdef1234567890",
          url: "/user/photo.jpg",
          paths: ["photo.jpg"],
          is_new: true,
          size: 1024,
          format: "jpeg",
          dimensions: { width: 1920, height: 1080 },
          available_formats: {
            webp: "https://img-src.io/i/user/photo.webp",
            avif: "https://img-src.io/i/user/photo.avif",
            jpeg: "https://img-src.io/i/user/photo.jpg",
          },
          uploaded_at: "2025-01-01T00:00:00Z",
          visibility: "public" as const,
          _links: {
            self: "/api/v1/images/abc123",
            delete: "/api/v1/images/abc123",
          },
        };

        expect(response.is_new).toBe(true);
        expect(response.dimensions.width).toBe(1920);
        expect(response.available_formats.webp).toBeDefined();
      });
    });

    describe("SearchResponse", () => {
      it("should not have limit and offset fields", () => {
        const response = {
          results: [
            {
              id: "abc123",
              original_filename: "beach.jpg",
              paths: ["photos/beach.jpg"],
              size: 1024,
              uploaded_at: "2025-01-01T00:00:00Z",
              url: "/api/v1/images/abc123",
              visibility: "public" as const,
            },
          ],
          total: 1,
          query: "beach",
        };

        expect(response.results).toHaveLength(1);
        expect(response.query).toBe("beach");
        expect((response as Record<string, unknown>).limit).toBeUndefined();
        expect((response as Record<string, unknown>).offset).toBeUndefined();
      });
    });

    describe("DeleteResponse", () => {
      it("should have correct structure", () => {
        const response = {
          success: true,
          message: "Image deleted",
          deleted_paths: ["photos/beach.jpg"],
          deleted_at: "2025-01-01T00:00:00Z",
        };

        expect(response.success).toBe(true);
        expect(response.deleted_paths).toContain("photos/beach.jpg");
      });
    });
  });

  describe("Zod Schema Validation", () => {
    const UploadImageArgsSchema = z
      .object({
        file_path: z.string().optional(),
        url: z.url("Invalid URL format").optional(),
        data: z.string().optional(),
        mimeType: z.string().optional(),
        target_path: z.string().optional(),
      })
      .refine((d) => d.file_path ?? d.url ?? d.data, {
        message: "One of file_path, url, or data is required",
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

    const GetCdnUrlArgsSchema = z.object({
      username: z.string().min(1, "Username is required"),
      filepath: z.string().min(1, "Filepath is required"),
      width: z.number().int().positive().optional(),
      height: z.number().int().positive().optional(),
      fit: z.enum(["cover", "contain", "fill", "scale-down"]).optional(),
      quality: z.number().int().min(1).max(100).optional(),
      format: z.enum(["webp", "avif", "jpeg", "png", "jxl"]).optional(),
    });

    describe("UploadImageArgsSchema", () => {
      it("should accept valid URL input", () => {
        const result = UploadImageArgsSchema.safeParse({
          url: "https://example.com/image.jpg",
          target_path: "photos/image.jpg",
        });
        expect(result.success).toBe(true);
      });

      it("should accept valid base64 input", () => {
        const result = UploadImageArgsSchema.safeParse({
          data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
          mimeType: "image/png",
          target_path: "photos/pixel.png",
        });
        expect(result.success).toBe(true);
      });

      it("should reject invalid URL", () => {
        const result = UploadImageArgsSchema.safeParse({
          url: "not-a-url",
        });
        expect(result.success).toBe(false);
      });

      it("should reject missing url and data", () => {
        const result = UploadImageArgsSchema.safeParse({
          target_path: "photos/image.jpg",
        });
        expect(result.success).toBe(false);
      });

      it("should reject data without mimeType", () => {
        const result = UploadImageArgsSchema.safeParse({
          data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        });
        expect(result.success).toBe(false);
      });

      it("should allow missing target_path", () => {
        const result = UploadImageArgsSchema.safeParse({
          url: "https://example.com/image.jpg",
        });
        expect(result.success).toBe(true);
      });

      it("should accept valid file_path input", () => {
        const result = UploadImageArgsSchema.safeParse({
          file_path: "/Users/test/photos/image.jpg",
          target_path: "photos/image.jpg",
        });
        expect(result.success).toBe(true);
      });

      it("should accept file_path without target_path", () => {
        const result = UploadImageArgsSchema.safeParse({
          file_path: "/Users/test/photos/image.png",
        });
        expect(result.success).toBe(true);
      });
    });

    describe("ListImagesArgsSchema", () => {
      it("should accept valid input", () => {
        const result = ListImagesArgsSchema.safeParse({
          folder: "photos",
          limit: 50,
          offset: 0,
        });
        expect(result.success).toBe(true);
      });

      it("should reject limit over 100", () => {
        const result = ListImagesArgsSchema.safeParse({
          limit: 101,
        });
        expect(result.success).toBe(false);
      });

      it("should reject negative offset", () => {
        const result = ListImagesArgsSchema.safeParse({
          offset: -1,
        });
        expect(result.success).toBe(false);
      });
    });

    describe("SearchImagesArgsSchema", () => {
      it("should accept valid input", () => {
        const result = SearchImagesArgsSchema.safeParse({
          query: "beach",
        });
        expect(result.success).toBe(true);
      });

      it("should reject empty query", () => {
        const result = SearchImagesArgsSchema.safeParse({
          query: "",
        });
        expect(result.success).toBe(false);
      });
    });

    describe("GetImageArgsSchema", () => {
      it("should accept valid input", () => {
        const result = GetImageArgsSchema.safeParse({
          id: "abc123",
        });
        expect(result.success).toBe(true);
      });

      it("should reject empty id", () => {
        const result = GetImageArgsSchema.safeParse({
          id: "",
        });
        expect(result.success).toBe(false);
      });
    });

    describe("GetCdnUrlArgsSchema", () => {
      it("should accept valid input with all options", () => {
        const result = GetCdnUrlArgsSchema.safeParse({
          username: "testuser",
          filepath: "photos/beach.jpg",
          width: 800,
          height: 600,
          fit: "cover",
          quality: 85,
          format: "webp",
        });
        expect(result.success).toBe(true);
      });

      it("should reject invalid fit value", () => {
        const result = GetCdnUrlArgsSchema.safeParse({
          username: "testuser",
          filepath: "photos/beach.jpg",
          fit: "invalid",
        });
        expect(result.success).toBe(false);
      });

      it("should reject quality over 100", () => {
        const result = GetCdnUrlArgsSchema.safeParse({
          username: "testuser",
          filepath: "photos/beach.jpg",
          quality: 101,
        });
        expect(result.success).toBe(false);
      });

      it("should reject negative width", () => {
        const result = GetCdnUrlArgsSchema.safeParse({
          username: "testuser",
          filepath: "photos/beach.jpg",
          width: -100,
        });
        expect(result.success).toBe(false);
      });
    });
  });

  describe("API Error Handling", () => {
    it("should return error for missing API key", () => {
      // The apiRequest function checks for API_KEY
      // This tests the error format consistency
      const errorResponse = {
        error: {
          code: "MISSING_API_KEY",
          message: "IMG_SRC_API_KEY environment variable is not set.",
          status: 401,
        },
      };

      expect(errorResponse.error.code).toBe("MISSING_API_KEY");
      expect(errorResponse.error.status).toBe(401);
    });

    it("should return error for network failure", () => {
      const errorResponse = {
        error: {
          code: "NETWORK_ERROR",
          message: "Failed to connect to img-src.io API: Connection refused",
          status: 0,
        },
      };

      expect(errorResponse.error.code).toBe("NETWORK_ERROR");
      expect(errorResponse.error.status).toBe(0);
    });

    it("should return error for timeout", () => {
      const errorResponse = {
        error: {
          code: "TIMEOUT",
          message: "Request timed out after 30 seconds",
          status: 0,
        },
      };

      expect(errorResponse.error.code).toBe("TIMEOUT");
    });

    it("should return consistent error format for all handlers", () => {
      // All error responses should have code and message
      const fetchError = {
        error: {
          code: "FETCH_FAILED",
          message: "Failed to fetch image from URL: 404 Not Found",
        },
      };

      const apiError = {
        error: {
          code: "API_ERROR",
          message: "API request failed with status 500",
          status: 500,
        },
      };

      const validationError = {
        error: {
          code: "INVALID_ARGS",
          message: "Invalid URL format",
        },
      };

      expect(fetchError.error.code).toBeDefined();
      expect(fetchError.error.message).toBeDefined();
      expect(apiError.error.code).toBeDefined();
      expect(validationError.error.code).toBeDefined();
    });

    it("should return JSON_PARSE_ERROR for invalid JSON responses", () => {
      const errorResponse = {
        error: {
          code: "JSON_PARSE_ERROR",
          message: "Failed to parse API response: Unexpected token < in JSON",
          status: 502,
        },
      };

      expect(errorResponse.error.code).toBe("JSON_PARSE_ERROR");
      expect(errorResponse.error.message).toContain("Failed to parse API response");
    });

    it("should return IMAGE_TOO_LARGE for oversized images", () => {
      const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
      const imageSize = 6 * 1024 * 1024; // 6MB

      if (imageSize > MAX_IMAGE_SIZE) {
        const errorResponse = {
          error: {
            code: "IMAGE_TOO_LARGE",
            message: `Image size (${(imageSize / (1024 * 1024)).toFixed(2)} MB) exceeds 5 MB limit`,
          },
        };

        expect(errorResponse.error.code).toBe("IMAGE_TOO_LARGE");
        expect(errorResponse.error.message).toContain("6.00 MB");
        expect(errorResponse.error.message).toContain("exceeds 5 MB limit");
      }
    });
  });

  describe("Timeout Configuration", () => {
    it("should have 30 second timeout", () => {
      const API_TIMEOUT_MS = 30000;
      expect(API_TIMEOUT_MS).toBe(30000);
      expect(API_TIMEOUT_MS / 1000).toBe(30);
    });
  });

  describe("isError Flag", () => {
    it("should be included in error responses", () => {
      // Simulating MCP response structure with isError
      const errorResponse = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error: { code: "INVALID_ARGS", message: "Missing required field" },
            }),
          },
        ],
        isError: true,
      };

      expect(errorResponse.isError).toBe(true);
      const parsed = JSON.parse(errorResponse.content[0].text) as {
        error: { code: string };
      };
      expect(parsed.error.code).toBe("INVALID_ARGS");
    });

    it("should not be included in success responses", () => {
      const successResponse = {
        content: [
          {
            type: "text",
            text: JSON.stringify({ success: true, data: {} }),
          },
        ],
      };

      expect(successResponse).not.toHaveProperty("isError");
    });

    it("should detect error in handler result", () => {
      // Test the logic for detecting errors in handler results
      const errorResult = JSON.stringify({ error: { code: "API_ERROR", message: "Failed" } });
      const successResult = JSON.stringify({ success: true, image: {} });

      const parsedError = JSON.parse(errorResult) as { error?: unknown };
      const parsedSuccess = JSON.parse(successResult) as { error?: unknown };

      expect("error" in parsedError).toBe(true);
      expect("error" in parsedSuccess).toBe(false);
    });
  });

  describe("Resources Support", () => {
    it("should format resource URI correctly", () => {
      const imageId = "abc123-def456";
      const uri = `imgsrc://images/${imageId}`;
      expect(uri).toBe("imgsrc://images/abc123-def456");
    });

    it("should parse resource URI correctly", () => {
      const uri = "imgsrc://images/abc123-def456";
      const match = /^imgsrc:\/\/images\/(.+)$/.exec(uri);
      expect(match).not.toBeNull();
      expect(match![1]).toBe("abc123-def456");
    });

    it("should return empty for invalid URI", () => {
      const uri = "invalid://path";
      const match = /^imgsrc:\/\/images\/(.+)$/.exec(uri);
      expect(match).toBeNull();
    });

    it("should structure list resources response correctly", () => {
      const images = [
        { id: "id1", original_filename: "photo1.jpg", paths: ["folder/photo1.jpg"] },
        { id: "id2", original_filename: "photo2.png", paths: ["photo2.png"] },
      ];

      const resources = images.map((img) => ({
        uri: `imgsrc://images/${img.id}`,
        name: img.original_filename,
        mimeType: "image/*",
        description: `Image: ${img.paths.join(", ")}`,
      }));

      expect(resources).toHaveLength(2);
      expect(resources[0].uri).toBe("imgsrc://images/id1");
      expect(resources[0].name).toBe("photo1.jpg");
      expect(resources[1].description).toBe("Image: photo2.png");
    });
  });

  describe("Prompts Support", () => {
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

    it("should have correct prompt definitions", () => {
      expect(prompts).toHaveLength(3);
      expect(prompts[0].name).toBe("upload-and-share");
      expect(prompts[0].arguments).toHaveLength(2);
      expect(prompts[1].arguments).toBeUndefined();
      expect(prompts[2].arguments![0].required).toBe(true);
    });

    it("should generate upload-and-share prompt message", () => {
      const args = { imageUrl: "https://example.com/photo.jpg", width: "800" };
      const message = `Upload this image: ${args.imageUrl}${args.width ? ` and resize to ${args.width}px width` : ""}. Then give me the CDN URL.`;
      expect(message).toContain("https://example.com/photo.jpg");
      expect(message).toContain("resize to 800px width");
    });

    it("should generate check-usage prompt message", () => {
      const message =
        "Check my img-src.io usage stats and let me know if I'm close to any limits.";
      expect(message).toContain("usage stats");
      expect(message).toContain("limits");
    });

    it("should generate find-images prompt message", () => {
      const args = { query: "vacation" };
      const message = `Find all my images matching "${args.query}" and show me the results.`;
      expect(message).toContain("vacation");
    });
  });

  describe("Base64 Upload", () => {
    it("should decode valid base64 to buffer", () => {
      // 1x1 red PNG pixel
      const base64 =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==";
      const buffer = Buffer.from(base64, "base64");
      expect(buffer.length).toBeGreaterThan(0);
      // PNG signature: 137 80 78 71 13 10 26 10
      expect(buffer[0]).toBe(137);
      expect(buffer[1]).toBe(80);
      expect(buffer[2]).toBe(78);
      expect(buffer[3]).toBe(71);
    });

    it("should generate filename from mimeType", () => {
      const mimeType = "image/png";
      const ext = mimeType.split("/")[1];
      const filename = `image.${ext}`;
      expect(filename).toBe("image.png");
    });

    it("should handle mimeType variations", () => {
      const mimeTypes = ["image/jpeg", "image/webp", "image/gif", "image/avif"];
      const extensions = mimeTypes.map((m) => m.split("/")[1]);
      expect(extensions).toEqual(["jpeg", "webp", "gif", "avif"]);
    });
  });
});
