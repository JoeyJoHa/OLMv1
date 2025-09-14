"""
NDJSON Parser

Handles parsing of newline-delimited JSON responses from catalogd service.
"""

import json
import logging
from typing import List, Dict, Any

from ..core.exceptions import ParsingError

logger = logging.getLogger(__name__)


class NDJSONParser:
    """Parses NDJSON (newline-delimited JSON) data efficiently"""
    
    def __init__(self):
        """Initialize NDJSON parser"""
        pass
    
    def parse_stream(self, text_body: str) -> List[Dict[str, Any]]:
        """
        Parse NDJSON (newline-delimited JSON) stream efficiently
        
        Args:
            text_body: Raw NDJSON text content
            
        Returns:
            List of parsed JSON objects
            
        Raises:
            ParsingError: If parsing fails
        """
        try:
            logger.debug(f"Parsing NDJSON response ({len(text_body)} bytes)")
            logger.debug(f"First 500 chars: {text_body[:500]}")
            logger.debug(f"Last 500 chars: {text_body[-500:]}")
            
            # Parse line by line (NDJSON format)
            items = []
            lines = text_body.strip().split('\n')
            logger.debug(f"Split into {len(lines)} lines")
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue  # Skip empty lines
                
                try:
                    item = json.loads(line)
                    items.append(item)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON on line {line_num}: {e}")
                    logger.debug(f"Problematic line: {line[:200]}...")
                    # Continue parsing other lines instead of failing completely
                    continue
            
            logger.info(f"Successfully parsed {len(items)} JSON objects from NDJSON stream")
            return items
            
        except Exception as e:
            raise ParsingError(f"Failed to parse NDJSON stream: {e}")
    
    def filter_by_schema(self, items: List[Dict[str, Any]], schema: str) -> List[Dict[str, Any]]:
        """
        Filter items by schema type
        
        Args:
            items: List of parsed JSON objects
            schema: Schema type to filter by (e.g., 'olm.package', 'olm.channel', 'olm.bundle')
            
        Returns:
            List of items matching the schema
        """
        try:
            filtered = [item for item in items if item.get('schema') == schema]
            logger.debug(f"Filtered {len(filtered)} items with schema '{schema}' from {len(items)} total items")
            return filtered
        except Exception as e:
            raise ParsingError(f"Failed to filter items by schema '{schema}': {e}")
    
    def extract_packages(self, items: List[Dict[str, Any]]) -> List[str]:
        """
        Extract package names from parsed catalog data
        
        Args:
            items: List of parsed JSON objects
            
        Returns:
            List of unique package names
        """
        try:
            packages = set()
            
            for item in items:
                if item.get('schema') == 'olm.package':
                    package_name = item.get('name')
                    if package_name:
                        packages.add(package_name)
            
            package_list = sorted(list(packages))
            logger.debug(f"Extracted {len(package_list)} unique packages")
            return package_list
            
        except Exception as e:
            raise ParsingError(f"Failed to extract packages: {e}")
    
    def extract_channels(self, items: List[Dict[str, Any]], package_name: str) -> List[str]:
        """
        Extract channel names for a specific package
        
        Args:
            items: List of parsed JSON objects
            package_name: Name of the package to get channels for
            
        Returns:
            List of channel names for the package
        """
        try:
            channels = set()
            
            for item in items:
                if (item.get('schema') == 'olm.channel' and 
                    item.get('package') == package_name):
                    channel_name = item.get('name')
                    if channel_name:
                        channels.add(channel_name)
            
            channel_list = sorted(list(channels))
            logger.debug(f"Extracted {len(channel_list)} channels for package '{package_name}'")
            return channel_list
            
        except Exception as e:
            raise ParsingError(f"Failed to extract channels for package '{package_name}': {e}")
    
    def extract_versions(self, items: List[Dict[str, Any]], package_name: str, channel_name: str) -> List[str]:
        """
        Extract version names for a specific package and channel
        
        Args:
            items: List of parsed JSON objects
            package_name: Name of the package
            channel_name: Name of the channel
            
        Returns:
            List of version names for the package/channel
        """
        try:
            versions = set()
            
            for item in items:
                if (item.get('schema') == 'olm.channel' and 
                    item.get('package') == package_name and
                    item.get('name') == channel_name):
                    
                    # Extract versions from channel entries
                    entries = item.get('entries', [])
                    for entry in entries:
                        version_name = entry.get('name')
                        if version_name:
                            # Extract version from bundle name (e.g., "operator.v1.2.3" -> "1.2.3")
                            if '.' in version_name and 'v' in version_name:
                                version_part = version_name.split('.v')[-1]
                                versions.add(version_part)
                            else:
                                versions.add(version_name)
            
            version_list = sorted(list(versions))
            logger.debug(f"Extracted {len(version_list)} versions for package '{package_name}' channel '{channel_name}'")
            return version_list
            
        except Exception as e:
            raise ParsingError(f"Failed to extract versions for package '{package_name}' channel '{channel_name}': {e}")
    
    def find_bundle_by_version(self, items: List[Dict[str, Any]], package_name: str, 
                              channel_name: str, version: str) -> Dict[str, Any]:
        """
        Find bundle metadata for a specific version
        
        Args:
            items: List of parsed JSON objects
            package_name: Name of the package
            channel_name: Name of the channel
            version: Version to find
            
        Returns:
            Bundle metadata dictionary
            
        Raises:
            ParsingError: If bundle not found or multiple matches
        """
        try:
            # First, try to find by exact version property
            for item in items:
                if (item.get('schema') == 'olm.bundle' and 
                    item.get('package') == package_name):
                    
                    properties = item.get('properties', [])
                    for prop in properties:
                        if (prop.get('type') == 'olm.bundle.object' and 
                            prop.get('value', {}).get('data', {}).get('spec', {}).get('version') == version):
                            
                            logger.debug(f"Found bundle by version property: {item.get('name')}")
                            return self._extract_bundle_metadata(item)
            
            # If not found by version property, try to find by bundle name pattern
            version_patterns = [f".v{version}", f"-v{version}", f"_{version}", version]
            
            for item in items:
                if (item.get('schema') == 'olm.bundle' and 
                    item.get('package') == package_name):
                    
                    bundle_name = item.get('name', '')
                    for pattern in version_patterns:
                        if pattern in bundle_name:
                            logger.debug(f"Found bundle by name pattern: {bundle_name}")
                            return self._extract_bundle_metadata(item)
            
            raise ParsingError(f"Bundle not found for package '{package_name}' version '{version}'")
            
        except ParsingError:
            raise
        except Exception as e:
            raise ParsingError(f"Failed to find bundle for version '{version}': {e}")
    
    def _extract_bundle_metadata(self, bundle_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract relevant metadata from bundle item
        
        Args:
            bundle_item: Bundle JSON object
            
        Returns:
            Extracted metadata dictionary
        """
        try:
            metadata = {
                'name': bundle_item.get('name'),
                'package': bundle_item.get('package'),
                'image': bundle_item.get('image'),
                'properties': bundle_item.get('properties', [])
            }
            
            # Extract additional metadata from properties
            for prop in metadata['properties']:
                if prop.get('type') == 'olm.bundle.object':
                    bundle_data = prop.get('value', {}).get('data', {})
                    spec = bundle_data.get('spec', {})
                    
                    metadata.update({
                        'olmv1_compatible': True,
                        'install_modes': self._extract_install_modes(spec),
                        'has_webhooks': self._has_webhooks(spec)
                    })
                    break
            
            return metadata
            
        except Exception as e:
            raise ParsingError(f"Failed to extract bundle metadata: {e}")
    
    def _extract_install_modes(self, spec: Dict[str, Any]) -> Dict[str, bool]:
        """Extract install modes from bundle spec"""
        install_modes = {}
        
        for mode in spec.get('installModes', []):
            mode_type = mode.get('type')
            supported = mode.get('supported', False)
            if mode_type:
                install_modes[mode_type] = supported
        
        return install_modes
    
    def _has_webhooks(self, spec: Dict[str, Any]) -> bool:
        """Check if bundle has webhooks"""
        webhooks = spec.get('webhookdefinitions', [])
        return len(webhooks) > 0
