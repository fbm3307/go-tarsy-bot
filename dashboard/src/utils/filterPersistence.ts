import type { SessionFilter, PaginationState, SortState } from '../types';

const FILTER_STORAGE_KEY = 'tarsy-dashboard-filters';
const PAGINATION_STORAGE_KEY = 'tarsy-dashboard-pagination';
const SORT_STORAGE_KEY = 'tarsy-dashboard-sort';
const ADVANCED_FILTERS_STORAGE_KEY = 'tarsy-dashboard-advanced-filters-shown';

/**
 * Utility functions for persisting dashboard state in localStorage
 * Used in Phase 6 for filter persistence across browser sessions
 */

// Filter persistence
export const saveFiltersToStorage = (filters: SessionFilter): void => {
  try {
    localStorage.setItem(FILTER_STORAGE_KEY, JSON.stringify(filters));
  } catch (error) {
    console.warn('Failed to save filters to localStorage:', error);
  }
};

export const loadFiltersFromStorage = (): SessionFilter | null => {
  try {
    const savedFilters = localStorage.getItem(FILTER_STORAGE_KEY);
    if (savedFilters) {
      return JSON.parse(savedFilters) as SessionFilter;
    }
  } catch (error) {
    console.warn('Failed to load filters from localStorage:', error);
  }
  return null;
};

export const clearFiltersFromStorage = (): void => {
  try {
    localStorage.removeItem(FILTER_STORAGE_KEY);
  } catch (error) {
    console.warn('Failed to clear filters from localStorage:', error);
  }
};

// Pagination persistence
export const savePaginationToStorage = (pagination: Partial<PaginationState>): void => {
  try {
    const savedPagination = loadPaginationFromStorage() || {};
    const updatedPagination = { ...savedPagination, ...pagination };
    localStorage.setItem(PAGINATION_STORAGE_KEY, JSON.stringify(updatedPagination));
  } catch (error) {
    console.warn('Failed to save pagination to localStorage:', error);
  }
};

export const loadPaginationFromStorage = (): Partial<PaginationState> | null => {
  try {
    const savedPagination = localStorage.getItem(PAGINATION_STORAGE_KEY);
    if (savedPagination) {
      return JSON.parse(savedPagination) as Partial<PaginationState>;
    }
  } catch (error) {
    console.warn('Failed to load pagination from localStorage:', error);
  }
  return null;
};

export const clearPaginationFromStorage = (): void => {
  try {
    localStorage.removeItem(PAGINATION_STORAGE_KEY);
  } catch (error) {
    console.warn('Failed to clear pagination from localStorage:', error);
  }
};

// Sort state persistence
export const saveSortToStorage = (sort: SortState): void => {
  try {
    localStorage.setItem(SORT_STORAGE_KEY, JSON.stringify(sort));
  } catch (error) {
    console.warn('Failed to save sort state to localStorage:', error);
  }
};

export const loadSortFromStorage = (): SortState | null => {
  try {
    const savedSort = localStorage.getItem(SORT_STORAGE_KEY);
    if (savedSort) {
      return JSON.parse(savedSort) as SortState;
    }
  } catch (error) {
    console.warn('Failed to load sort state from localStorage:', error);
  }
  return null;
};

export const clearSortFromStorage = (): void => {
  try {
    localStorage.removeItem(SORT_STORAGE_KEY);
  } catch (error) {
    console.warn('Failed to clear sort state from localStorage:', error);
  }
};

// Advanced filters visibility state
export const saveAdvancedFiltersVisibility = (isVisible: boolean): void => {
  try {
    localStorage.setItem(ADVANCED_FILTERS_STORAGE_KEY, JSON.stringify(isVisible));
  } catch (error) {
    console.warn('Failed to save advanced filters visibility to localStorage:', error);
  }
};

export const loadAdvancedFiltersVisibility = (): boolean => {
  try {
    const savedVisibility = localStorage.getItem(ADVANCED_FILTERS_STORAGE_KEY);
    if (savedVisibility) {
      return JSON.parse(savedVisibility) as boolean;
    }
  } catch (error) {
    console.warn('Failed to load advanced filters visibility from localStorage:', error);
  }
  return false; // Default to hidden
};

// Clear all dashboard state
export const clearAllDashboardState = (): void => {
  clearFiltersFromStorage();
  clearPaginationFromStorage();
  clearSortFromStorage();
  try {
    localStorage.removeItem(ADVANCED_FILTERS_STORAGE_KEY);
  } catch (error) {
    console.warn('Failed to clear advanced filters visibility from localStorage:', error);
  }
};

// Default values for initialization
export const getDefaultFilters = (): SessionFilter => ({
  search: '',
  status: [],
  agent_type: [],
  alert_type: [],
  start_date: null,
  end_date: null,
  time_range_preset: null
});

export const getDefaultPagination = (): PaginationState => ({
  page: 1,
  pageSize: 10,
  totalPages: 1,
  totalItems: 0
});

export const getDefaultSort = (): SortState => ({
  field: 'started_at_us',
  direction: 'desc'
});

// Utility to merge saved state with defaults
export const mergeWithDefaults = <T>(saved: Partial<T> | null, defaults: T): T => {
  if (!saved) return defaults;
  return { ...defaults, ...saved };
}; 