"""
Catalogd Response Cache

Implements intelligent caching for catalogd responses to improve performance.
"""

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..core.constants import FileConstants
from ..core.utils import format_bytes

logger = logging.getLogger(__name__)


class CatalogdCache:
    """Intelligent cache for catalogd responses"""
    
    def __init__(self, cache_dir: Optional[str] = None, ttl: int = 300):
        """
        Initialize catalogd cache
        
        Args:
            cache_dir: Directory to store cache files (default: system temp)
            ttl: Time-to-live for cache entries in seconds (default: 5 minutes)
        """
        self.ttl = ttl
        
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            # Use system temp directory with rbac-manager subdirectory
            self.cache_dir = Path(tempfile.gettempdir()) / FileConstants.CACHE_DIR_NAME
        
        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Clean up old cache entries on initialization
        self._cleanup_expired_entries()
        
        logger.debug(f"Initialized catalogd cache at: {self.cache_dir}")
    
    def _generate_cache_key(self, catalog_name: str, url_path: str) -> str:
        """
        Generate a unique cache key for a request
        
        Args:
            catalog_name: Name of the catalog
            url_path: API endpoint path
            
        Returns:
            str: Unique cache key
        """
        # Create a hash of the catalog and path for consistent key generation
        key_data = f"{catalog_name}:{url_path}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _get_cache_file_path(self, cache_key: str) -> Path:
        """Get the file path for a cache entry"""
        return self.cache_dir / f"{cache_key}.json"
    
    def _get_metadata_file_path(self, cache_key: str) -> Path:
        """Get the metadata file path for a cache entry"""
        return self.cache_dir / f"{cache_key}.meta"
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """
        Check if a cache entry is still valid
        
        Args:
            cache_key: Cache key to check
            
        Returns:
            bool: True if cache is valid and not expired
        """
        cache_file = self._get_cache_file_path(cache_key)
        meta_file = self._get_metadata_file_path(cache_key)
        
        if not cache_file.exists() or not meta_file.exists():
            return False
        
        try:
            # Read metadata
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
            
            # Check if expired
            cached_time = metadata.get('timestamp', 0)
            current_time = time.time()
            
            if current_time - cached_time > self.ttl:
                logger.debug(f"Cache entry expired: {cache_key}")
                return False
            
            logger.debug(f"Cache entry valid: {cache_key} (age: {current_time - cached_time:.1f}s)")
            return True
            
        except Exception as e:
            logger.debug(f"Error checking cache validity: {e}")
            return False
    
    def get(self, catalog_name: str, url_path: str) -> Optional[str]:
        """
        Get cached response data
        
        Args:
            catalog_name: Name of the catalog
            url_path: API endpoint path
            
        Returns:
            Optional[str]: Cached response data or None if not found/expired
        """
        cache_key = self._generate_cache_key(catalog_name, url_path)
        
        if not self._is_cache_valid(cache_key):
            return None
        
        try:
            cache_file = self._get_cache_file_path(cache_key)
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = f.read()
            
            logger.debug(f"Cache hit: {catalog_name}{url_path} ({len(data)} bytes)")
            return data
            
        except Exception as e:
            logger.debug(f"Error reading from cache: {e}")
            return None
    
    def put(self, catalog_name: str, url_path: str, data: str) -> None:
        """
        Store response data in cache
        
        Args:
            catalog_name: Name of the catalog
            url_path: API endpoint path
            data: Response data to cache
        """
        cache_key = self._generate_cache_key(catalog_name, url_path)
        
        try:
            # Write data file
            cache_file = self._get_cache_file_path(cache_key)
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(data)
            
            # Write metadata file
            meta_file = self._get_metadata_file_path(cache_key)
            metadata = {
                'timestamp': time.time(),
                'catalog_name': catalog_name,
                'url_path': url_path,
                'size': len(data)
            }
            
            with open(meta_file, 'w') as f:
                json.dump(metadata, f)
            
            logger.debug(f"Cached response: {catalog_name}{url_path} ({len(data)} bytes)")
            
        except Exception as e:
            logger.warning(f"Failed to cache response: {e}")
    
    def invalidate(self, catalog_name: str, url_path: str = None) -> None:
        """
        Invalidate cache entries
        
        Args:
            catalog_name: Name of the catalog
            url_path: Specific path to invalidate (if None, invalidates all for catalog)
        """
        if url_path:
            # Invalidate specific entry
            cache_key = self._generate_cache_key(catalog_name, url_path)
            self._remove_cache_entry(cache_key)
        else:
            # Invalidate all entries for catalog
            for cache_file in self.cache_dir.glob("*.meta"):
                try:
                    with open(cache_file, 'r') as f:
                        metadata = json.load(f)
                    
                    if metadata.get('catalog_name') == catalog_name:
                        cache_key = cache_file.stem
                        self._remove_cache_entry(cache_key)
                        
                except Exception as e:
                    logger.debug(f"Error checking cache file {cache_file}: {e}")
    
    def _remove_cache_entry(self, cache_key: str) -> None:
        """Remove a cache entry and its metadata"""
        try:
            cache_file = self._get_cache_file_path(cache_key)
            meta_file = self._get_metadata_file_path(cache_key)
            
            if cache_file.exists():
                cache_file.unlink()
            if meta_file.exists():
                meta_file.unlink()
                
            logger.debug(f"Removed cache entry: {cache_key}")
            
        except Exception as e:
            logger.debug(f"Error removing cache entry {cache_key}: {e}")
    
    def _cleanup_expired_entries(self) -> None:
        """Clean up expired cache entries"""
        try:
            current_time = time.time()
            removed_count = 0
            
            for meta_file in self.cache_dir.glob("*.meta"):
                try:
                    with open(meta_file, 'r') as f:
                        metadata = json.load(f)
                    
                    cached_time = metadata.get('timestamp', 0)
                    if current_time - cached_time > self.ttl:
                        cache_key = meta_file.stem
                        self._remove_cache_entry(cache_key)
                        removed_count += 1
                        
                except Exception as e:
                    logger.debug(f"Error processing cache file {meta_file}: {e}")
            
            if removed_count > 0:
                logger.debug(f"Cleaned up {removed_count} expired cache entries")
                
        except Exception as e:
            logger.debug(f"Error during cache cleanup: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics
        
        Returns:
            Dict with cache statistics
        """
        try:
            cache_files = list(self.cache_dir.glob("*.json"))
            meta_files = list(self.cache_dir.glob("*.meta"))
            
            total_size = sum(f.stat().st_size for f in cache_files if f.exists())
            
            # Count entries by catalog
            catalog_counts = {}
            for meta_file in meta_files:
                try:
                    with open(meta_file, 'r') as f:
                        metadata = json.load(f)
                    catalog_name = metadata.get('catalog_name', 'unknown')
                    catalog_counts[catalog_name] = catalog_counts.get(catalog_name, 0) + 1
                except Exception:
                    continue
            
            return {
                'cache_dir': str(self.cache_dir),
                'ttl': self.ttl,
                'total_entries': len(cache_files),
                'total_size_bytes': total_size,
                'total_size_human': format_bytes(total_size),
                'entries_by_catalog': catalog_counts
            }
            
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {'error': str(e)}
    
    
    def clear_all(self) -> None:
        """Clear all cache entries"""
        try:
            removed_count = 0
            for cache_file in self.cache_dir.glob("*"):
                if cache_file.is_file():
                    cache_file.unlink()
                    removed_count += 1
            
            logger.info(f"Cleared all cache entries ({removed_count} files)")
            
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
