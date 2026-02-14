/**
 * Security utility functions for the SIEM frontend.
 * Provides safe URL validation, input sanitization, and other security helpers.
 */

/**
 * Validates a URL and returns it only if it uses a safe protocol (http/https).
 * Returns '#' for invalid, empty, or potentially dangerous URLs (javascript:, data:, etc.)
 * @param {string} url - The URL to validate
 * @returns {string} The safe URL or '#' if invalid
 */
export function safeUrl(url) {
  if (!url || typeof url !== 'string') {
    return '#';
  }

  const trimmed = url.trim();

  // Only allow http and https protocols
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return trimmed;
    }
    return '#';
  } catch {
    // If URL parsing fails, check if it's a relative URL (starts with /)
    if (trimmed.startsWith('/')) {
      return trimmed;
    }
    return '#';
  }
}

/**
 * Checks if a URL is safe for use in href attributes.
 * @param {string} url - The URL to check
 * @returns {boolean} true if the URL is safe
 */
export function isUrlSafe(url) {
  return safeUrl(url) !== '#';
}
