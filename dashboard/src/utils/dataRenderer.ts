/**
 * Data rendering utilities for flexible alert data structures
 * Provides safe rendering with XSS prevention and proper formatting
 */

import { formatTimestamp } from './timestamp';

/**
 * Basic HTML escaping for XSS prevention
 */
const escapeHtml = (text: string): string => {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
};

/**
 * Check if a field name suggests it contains a timestamp
 */
const isTimestampField = (fieldName: string): boolean => {
  const timestampPatterns = [
    'timestamp', 'time', 'created', 'updated', 'modified', 
    'created_at', 'updated_at', 'event_time', 'alert_created',
    'processed_at', 'started_at', 'finished_at'
  ];
  
  const lowerFieldName = fieldName.toLowerCase();
  return timestampPatterns.some(pattern => lowerFieldName.includes(pattern));
};

/**
 * Check if a numeric value looks like a Unix timestamp
 */
const isUnixTimestamp = (value: number): boolean => {
  // Unix timestamps should be positive integers
  if (!Number.isInteger(value) || value <= 0) {
    return false;
  }
  
  // Check for reasonable timestamp ranges:
  // - Seconds: between 1970 and 2099 (946684800 to 4102444800)
  // - Milliseconds: between 1970 and 2099 (* 1000)
  // - Microseconds: between 1970 and 2099 (* 1000000)
  
  const year1970Seconds = 0;
  const year2099Seconds = 4102444800;
  const year1970Milliseconds = year1970Seconds * 1000;
  const year2099Milliseconds = year2099Seconds * 1000;
  const year1970Microseconds = year1970Seconds * 1000000;
  const year2099Microseconds = year2099Seconds * 1000000;
  
  // Check if it's in microseconds range (most likely in our system)
  if (value >= year1970Microseconds && value <= year2099Microseconds) {
    return true;
  }
  
  // Check if it's in milliseconds range
  if (value >= year1970Milliseconds && value <= year2099Milliseconds) {
    return true;
  }
  
  // Check if it's in seconds range
  if (value >= year1970Seconds && value <= year2099Seconds) {
    return true;
  }
  
  return false;
};

/**
 * Convert various timestamp formats to microseconds
 */
const normalizeTimestamp = (value: number): number => {
  const year1970Microseconds = 0;
  const year2099Microseconds = 4102444800 * 1000000;
  const year1970Milliseconds = 0;
  const year2099Milliseconds = 4102444800 * 1000;
  const year1970Seconds = 0;
  const year2099Seconds = 4102444800;
  
  // Already in microseconds
  if (value >= year1970Microseconds && value <= year2099Microseconds) {
    return value;
  }
  
  // Convert from milliseconds to microseconds
  if (value >= year1970Milliseconds && value <= year2099Milliseconds) {
    return value * 1000;
  }
  
  // Convert from seconds to microseconds
  if (value >= year1970Seconds && value <= year2099Seconds) {
    return value * 1000000;
  }
  
  return value; // Return as-is if not in expected ranges
};

export interface RenderableValue {
  type: 'simple' | 'json' | 'multiline' | 'url' | 'timestamp';
  content: string;
  displayValue: string;
  timestampUs?: number; // For timestamp type, store the original timestamp value
}

/**
 * Safely render any value to a displayable format with comprehensive error handling
 * Handles objects, arrays, strings, numbers, booleans, etc. with fallbacks for corrupted data
 */
export const renderValue = (value: any, fieldName?: string): RenderableValue => {
  try {
    // Handle null, undefined, and empty values
    if (value === null || value === undefined) {
      return {
        type: 'simple',
        content: 'N/A',
        displayValue: 'N/A'
      };
    }

    // Handle circular references and extremely large objects
    try {
      // Test if value can be JSON stringified (detects circular references)
      JSON.stringify(value);
    } catch (circularError) {
      // Handle circular references or non-serializable objects
      if (typeof value === 'object') {
        return {
          type: 'simple',
          content: '[Object with circular reference]',
          displayValue: '[Object with circular reference]'
        };
      } else if (typeof value === 'function') {
        return {
          type: 'simple',
          content: '[Function]',
          displayValue: '[Function]'
        };
      } else {
        return {
          type: 'simple',
          content: '[Non-serializable value]',
          displayValue: '[Non-serializable value]'
        };
      }
    }

    // Handle objects and arrays - format as JSON with size limits
    if (typeof value === 'object') {
      try {
        const jsonString = JSON.stringify(value, null, 2);
        
        // Check if JSON is too large (> 100KB)
        if (jsonString.length > 100000) {
          return {
            type: 'simple',
            content: `[Large object - ${Object.keys(value).length} keys, ${jsonString.length} chars]`,
            displayValue: `[Large object - ${Object.keys(value).length} keys]`
          };
        }
        
        return {
          type: 'json',
          content: escapeHtml(jsonString),
          displayValue: jsonString
        };
      } catch (jsonError) {
        // Fallback for objects that can't be JSON stringified
        return {
          type: 'simple',
          content: `[Object - ${Object.keys(value || {}).length} keys]`,
          displayValue: `[Object - ${Object.keys(value || {}).length} keys]`
        };
      }
    }

    // Handle strings with safety checks
    if (typeof value === 'string') {
      // Limit string length to prevent UI issues
      const maxLength = 50000; // 50KB limit
      const truncatedValue = value.length > maxLength ? value.substring(0, maxLength) + '... [truncated]' : value;
      
      // Check if it's a URL
      try {
        if (isValidUrl(truncatedValue)) {
          return {
            type: 'url',
            content: escapeHtml(truncatedValue),
            displayValue: truncatedValue
          };
        }
      } catch (urlError) {
        // URL validation failed, treat as regular string
      }

      // Check if it's a JSON string
      try {
        if (isJsonString(truncatedValue)) {
          const parsed = JSON.parse(truncatedValue);
          const jsonString = JSON.stringify(parsed, null, 2);
          return {
            type: 'json',
            content: escapeHtml(jsonString),
            displayValue: jsonString
          };
        }
      } catch (jsonParseError) {
        // JSON parsing failed, treat as regular string
      }

      // Check if it's multiline
      if (truncatedValue.includes('\n')) {
        return {
          type: 'multiline',
          content: escapeHtml(truncatedValue),
          displayValue: truncatedValue
        };
      }

      // Regular string
      return {
        type: 'simple',
        content: escapeHtml(truncatedValue),
        displayValue: truncatedValue
      };
    }

    // Handle numbers with safety checks and timestamp detection
    if (typeof value === 'number') {
      // Check for special number values
      if (!isFinite(value)) {
        return {
          type: 'simple',
          content: isNaN(value) ? 'NaN' : (value > 0 ? 'Infinity' : '-Infinity'),
          displayValue: isNaN(value) ? 'NaN' : (value > 0 ? 'Infinity' : '-Infinity')
        };
      }
      
      // Check if this looks like a timestamp (by field name or value pattern)
      const isTimestampByName = fieldName ? isTimestampField(fieldName) : false;
      const isTimestampByValue = isUnixTimestamp(value);
      
      if (isTimestampByName || isTimestampByValue) {
        try {
          const normalizedTimestamp = normalizeTimestamp(value);
          const formattedTime = formatTimestamp(normalizedTimestamp, 'absolute');
          const relativeTime = formatTimestamp(normalizedTimestamp, 'relative');
          
          return {
            type: 'timestamp',
            content: escapeHtml(`${formattedTime} (${relativeTime})`),
            displayValue: `${formattedTime} (${relativeTime})`,
            timestampUs: normalizedTimestamp
          };
        } catch (timestampError) {
          // If timestamp formatting fails, fall back to regular number display
          console.warn('Failed to format timestamp:', value, timestampError);
        }
      }
      
      // Regular number
      return {
        type: 'simple',
        content: escapeHtml(String(value)),
        displayValue: String(value)
      };
    }

    // Handle booleans
    if (typeof value === 'boolean') {
      return {
        type: 'simple',
        content: String(value),
        displayValue: String(value)
      };
    }

    // Handle symbols
    if (typeof value === 'symbol') {
      return {
        type: 'simple',
        content: '[Symbol]',
        displayValue: '[Symbol]'
      };
    }

    // Handle BigInt
    if (typeof value === 'bigint') {
      return {
        type: 'simple',
        content: escapeHtml(String(value) + 'n'),
        displayValue: String(value) + 'n'
      };
    }

    // Fallback for unknown types
    return {
      type: 'simple',
      content: escapeHtml(String(value)),
      displayValue: String(value)
    };

  } catch (error) {
    // Ultimate fallback for any unexpected errors
    console.error('Error in renderValue:', error, 'Value:', value);
    
    return {
      type: 'simple',
      content: '[Error rendering value]',
      displayValue: '[Error rendering value]'
    };
  }
};

/**
 * Format key names for display (convert snake_case to Title Case)
 */
export const formatKeyName = (key: string): string => {
  return key
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
};

/**
 * Check if a string is a valid URL
 */
const isValidUrl = (str: string): boolean => {
  try {
    new URL(str);
    return str.startsWith('http://') || str.startsWith('https://');
  } catch {
    return false;
  }
};

/**
 * Check if a string is a JSON string
 */
const isJsonString = (str: string): boolean => {
  if (typeof str !== 'string') return false;
  const trimmed = str.trim();
  return (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
         (trimmed.startsWith('[') && trimmed.endsWith(']'));
};

/**
 * Get appropriate priority for field display order
 * Lower numbers = higher priority (displayed first)
 */
export const getFieldPriority = (key: string): number => {
  const priorities: Record<string, number> = {
    'alert_type': 1,
    'severity': 2,
    'environment': 3,
    'timestamp_us': 4,
    'message': 5,
    'cluster': 6,
    'namespace': 7,
    'pod': 8,
    'runbook': 99, // Display runbook at the end
    'context': 98  // Display context near the end
  };

  return priorities[key] || 50; // Default priority for unknown fields
};

/**
 * Sort alert data fields by priority for consistent display
 */
export const sortAlertFields = (alertData: Record<string, any>): Array<[string, any]> => {
  return Object.entries(alertData)
    .sort(([keyA], [keyB]) => getFieldPriority(keyA) - getFieldPriority(keyB));
};