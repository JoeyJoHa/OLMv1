"""
NDJSON Parser

Handles parsing of newline-delimited JSON responses from catalogd service.
"""

import json
import logging
from typing import List, Dict, Any, Callable, Optional

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
    
    def _filter_and_extract(self, items: List[Dict[str, Any]], filter_func: Callable[[Dict[str, Any]], bool], 
                           key_to_extract: str, transform_func: Optional[Callable[[str], str]] = None) -> List[str]:
        """
        Generic helper method to filter items and extract unique values
        
        Args:
            items: List of dictionaries to process
            filter_func: Function that takes an item and returns True if it should be included
            key_to_extract: Key name to extract from matching items
            transform_func: Optional function to transform extracted values
            
        Returns:
            Sorted list of unique extracted values
        """
        values = set()
        
        for item in items:
            if filter_func(item):
                value = item.get(key_to_extract)
                if value:
                    if transform_func:
                        value = transform_func(value)
                    values.add(value)
        
        return sorted(list(values))
    
    def _extract_data_with_mapping(self, source: Dict[str, Any], mapping_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Data-driven helper function that extracts data from a source dictionary using a mapping configuration
        
        This eliminates repetitive .get() calls by using a declarative mapping approach.
        
        Args:
            source: Source dictionary to extract data from
            mapping_config: Configuration dictionary defining the extraction mapping
                Format: {
                    'output_key': {
                        'path': 'source.path.to.value',  # Dot notation path
                        'default': default_value,        # Optional default value
                        'transform': callable,           # Optional transformation function
                        'condition': callable            # Optional condition function
                    }
                }
                
        Returns:
            Dictionary with extracted data based on mapping configuration
        """
        result = {}
        
        for output_key, config in mapping_config.items():
            try:
                # Handle different configuration formats
                if isinstance(config, str):
                    # Simple string path
                    path = config
                    default = None
                    transform = None
                    condition = None
                elif isinstance(config, dict):
                    # Full configuration object
                    path = config.get('path', output_key)
                    default = config.get('default')
                    transform = config.get('transform')
                    condition = config.get('condition')
                else:
                    # Direct value
                    result[output_key] = config
                    continue
                
                # Extract value using dot notation path
                value = self._get_nested_value(source, path, default)
                
                # Apply condition if specified
                if condition and not condition(value):
                    value = default
                
                # Apply transformation if specified
                if transform and value is not None:
                    value = transform(value)
                
                result[output_key] = value
                
            except Exception as e:
                logger.debug(f"Error extracting {output_key} from path {config}: {e}")
                # Use default value or None if extraction fails
                default_val = config.get('default') if isinstance(config, dict) else None
                result[output_key] = default_val
        
        return result
    
    def _get_nested_value(self, data: Dict[str, Any], path: str, default: Any = None) -> Any:
        """
        Get nested value from dictionary using dot notation path
        
        Args:
            data: Source dictionary
            path: Dot notation path (e.g., 'spec.provider.name')
            default: Default value if path not found
            
        Returns:
            Value at the specified path or default
        """
        try:
            current = data
            for key in path.split('.'):
                if isinstance(current, dict):
                    current = current.get(key)
                else:
                    return default
                
                if current is None:
                    return default
            
            return current
        except Exception:
            return default
    
    def extract_packages(self, items: List[Dict[str, Any]]) -> List[str]:
        """
        Extract package names from parsed catalog data
        
        Args:
            items: List of parsed JSON objects
            
        Returns:
            List of unique package names
        """
        try:
            package_list = self._filter_and_extract(
                items, 
                lambda item: item.get('schema') == 'olm.package', 
                'name'
            )
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
            channel_list = self._filter_and_extract(
                items,
                lambda item: (item.get('schema') == 'olm.channel' and 
                             item.get('package') == package_name),
                'name'
            )
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
        Extract essential metadata from bundle item - focused on key fields only
        
        Args:
            bundle_item: Bundle JSON object
            
        Returns:
            Minimal metadata dictionary with essential fields
        """
        try:
            # Essential metadata only
            metadata = {
                'bundle_image': bundle_item.get('image'),
                'olmv1_compatible': False,
                'install_modes': {},
                'webhooks': {
                    'has_webhooks': False,
                    'webhook_types': []
                }
            }
            
            # Parse properties for detailed information
            properties = bundle_item.get('properties', [])
            
            for prop in properties:
                prop_type = prop.get('type')
                prop_value = prop.get('value', {})
                
                if prop_type == 'olm.bundle.object':
                    # This contains the ClusterServiceVersion (CSV) data
                    bundle_data = prop_value.get('data', {})
                    metadata['olmv1_compatible'] = True
                    
                    # Extract install modes and webhooks only
                    spec = bundle_data.get('spec', {})
                    metadata['install_modes'] = self._extract_install_modes(spec)
                    metadata['webhooks'] = self._extract_webhook_info_minimal(spec)
                    
                elif prop_type == 'olm.csv.metadata':
                    # This is the main CSV metadata - indicates OLMv1 compatibility
                    metadata['olmv1_compatible'] = True
                    
                    # Extract install modes from CSV metadata
                    install_modes = {}
                    for mode in prop_value.get('installModes', []):
                        mode_type = mode.get('type')
                        supported = mode.get('supported', False)
                        if mode_type:
                            install_modes[mode_type] = supported
                    metadata['install_modes'] = install_modes
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error extracting bundle metadata: {e}")
            # Fallback to minimal metadata if parsing fails
            return {
                'bundle_image': bundle_item.get('image'),
                'olmv1_compatible': False,
                'install_modes': {},
                'webhooks': {'has_webhooks': False, 'webhook_types': []},
                'error': f"Failed to parse metadata: {e}"
            }
    
    def _extract_install_modes(self, spec: Dict[str, Any]) -> Dict[str, bool]:
        """Extract install modes from bundle spec"""
        install_modes = {}
        
        for mode in spec.get('installModes', []):
            mode_type = mode.get('type')
            supported = mode.get('supported', False)
            if mode_type:
                install_modes[mode_type] = supported
        
        return install_modes
    
    def _extract_csv_metadata(self, bundle_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CSV metadata from bundle data (olm.bundle.object) using data-driven mapping"""
        try:
            # Define extraction mapping configuration
            csv_mapping = {
                'name': 'metadata.name',
                'namespace': 'metadata.namespace', 
                'display_name': 'spec.displayName',
                'description': 'spec.description',
                'version': 'spec.version',
                'provider': 'spec.provider.name',
                'maturity': 'spec.maturity',
                'keywords': {'path': 'spec.keywords', 'default': []},
                'maintainers': {'path': 'spec.maintainers', 'default': []},
                'links': {'path': 'spec.links', 'default': []},
                'icon': {
                    'path': 'spec.icon',
                    'default': {},
                    'transform': lambda icons: icons[0] if icons else {}
                }
            }
            
            return self._extract_data_with_mapping(bundle_data, csv_mapping)
            
        except Exception as e:
            logger.debug(f"Error extracting CSV metadata: {e}")
            return {}
    
    def _extract_csv_from_metadata(self, csv_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CSV metadata from olm.csv.metadata property using data-driven mapping"""
        try:
            # Define extraction mapping configuration
            metadata_mapping = {
                'display_name': 'displayName',
                'description': 'description',
                'version': 'version',
                'provider': 'provider.name',
                'maturity': 'maturity',
                'keywords': {'path': 'keywords', 'default': []},
                'maintainers': {'path': 'maintainers', 'default': []},
                'links': {'path': 'links', 'default': []},
                'annotations': {'path': 'annotations', 'default': {}},
                'labels': {'path': 'labels', 'default': {}},
                'capabilities': 'annotations.capabilities',
                'categories': 'annotations.categories',
                'container_image': 'annotations.containerImage',
                'repository': 'annotations.repository',
                'created_at': 'annotations.createdAt'
            }
            
            return self._extract_data_with_mapping(csv_metadata, metadata_mapping)
            
        except Exception as e:
            logger.debug(f"Error extracting CSV from metadata: {e}")
            return {}
    
    def _extract_webhook_info_minimal(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract minimal webhook information from bundle spec using data-driven mapping"""
        try:
            # Define extraction mapping configuration
            webhook_mapping = {
                'has_webhooks': {
                    'path': 'webhookdefinitions',
                    'default': False,
                    'transform': lambda webhooks: len(webhooks) > 0 if webhooks else False
                },
                'webhook_types': {
                    'path': 'webhookdefinitions',
                    'default': [],
                    'transform': lambda webhooks: list(set(
                        webhook.get('type', 'unknown') for webhook in webhooks
                    )) if webhooks else []
                }
            }
            
            return self._extract_data_with_mapping(spec, webhook_mapping)
            
        except Exception as e:
            logger.debug(f"Error extracting webhook info: {e}")
            return {'has_webhooks': False, 'webhook_types': []}
    
    def _extract_webhook_info(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract webhook information from bundle spec (legacy method for compatibility)"""
        try:
            webhooks = spec.get('webhookdefinitions', [])
            webhook_info = {
                'has_webhooks': len(webhooks) > 0,
                'webhook_types': [],
                'webhook_details': []
            }
            
            for webhook in webhooks:
                webhook_type = webhook.get('type', 'unknown')
                webhook_info['webhook_types'].append(webhook_type)
                webhook_info['webhook_details'].append({
                    'type': webhook_type,
                    'admission_review_versions': webhook.get('admissionReviewVersions', []),
                    'container_port': webhook.get('containerPort'),
                    'deployment_name': webhook.get('deploymentName'),
                    'generate_name': webhook.get('generateName'),
                    'rules': webhook.get('rules', [])
                })
            
            # Remove duplicates from webhook_types
            webhook_info['webhook_types'] = list(set(webhook_info['webhook_types']))
            
            return webhook_info
        except Exception as e:
            logger.debug(f"Error extracting webhook info: {e}")
            return {'has_webhooks': False, 'webhook_types': []}
    
    def _extract_related_images(self, spec: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract related images from bundle spec"""
        try:
            related_images = []
            
            # From relatedImages field
            for img in spec.get('relatedImages', []):
                related_images.append({
                    'name': img.get('name'),
                    'image': img.get('image'),
                    'source': 'relatedImages'
                })
            
            # From install strategy deployments
            install_strategy = spec.get('install', {}).get('spec', {})
            deployments = install_strategy.get('deployments', [])
            
            for deployment in deployments:
                containers = deployment.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
                for container in containers:
                    image = container.get('image')
                    if image:
                        related_images.append({
                            'name': container.get('name'),
                            'image': image,
                            'source': 'deployment_containers'
                        })
            
            return related_images
        except Exception as e:
            logger.debug(f"Error extracting related images: {e}")
            return []
    
    def _has_webhooks(self, spec: Dict[str, Any]) -> bool:
        """Check if bundle has webhooks (legacy method for compatibility)"""
        webhooks = spec.get('webhookdefinitions', [])
        return len(webhooks) > 0
