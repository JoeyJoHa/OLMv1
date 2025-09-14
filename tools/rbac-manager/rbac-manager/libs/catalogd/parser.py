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
        Extract relevant metadata from bundle item with enhanced parsing
        
        Args:
            bundle_item: Bundle JSON object
            
        Returns:
            Structured metadata dictionary with parsed fields
        """
        try:
            # Base metadata
            metadata = {
                'bundle_name': bundle_item.get('name'),
                'package': bundle_item.get('package'),
                'bundle_image': bundle_item.get('image'),
                'olmv1_compatible': False,
                'install_modes': {},
                'webhooks': {
                    'has_webhooks': False,
                    'webhook_types': []
                },
                'csv_metadata': {},
                'dependencies': [],
                'related_images': [],
                'properties_summary': {}
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
                    
                    # Extract CSV metadata
                    csv_metadata = self._extract_csv_metadata(bundle_data)
                    metadata['csv_metadata'] = csv_metadata
                    
                    # Extract install modes
                    spec = bundle_data.get('spec', {})
                    metadata['install_modes'] = self._extract_install_modes(spec)
                    
                    # Extract webhook information
                    metadata['webhooks'] = self._extract_webhook_info(spec)
                    
                    # Extract related images
                    metadata['related_images'] = self._extract_related_images(spec)
                    
                elif prop_type == 'olm.package':
                    # Package-level metadata
                    metadata['properties_summary']['package_info'] = prop_value
                    
                elif prop_type == 'olm.bundle.mediatype':
                    # Bundle media type
                    metadata['properties_summary']['media_type'] = prop_value.get('type')
                    
                elif prop_type == 'olm.csv.metadata':
                    # This is the main CSV metadata - indicates OLMv1 compatibility
                    metadata['olmv1_compatible'] = True
                    metadata['csv_metadata'] = self._extract_csv_from_metadata(prop_value)
                    
                    # Extract install modes from CSV metadata
                    install_modes = {}
                    for mode in prop_value.get('installModes', []):
                        mode_type = mode.get('type')
                        supported = mode.get('supported', False)
                        if mode_type:
                            install_modes[mode_type] = supported
                    metadata['install_modes'] = install_modes
                    
                elif prop_type == 'olm.gvk':
                    # Group/Version/Kind information
                    if 'provided_apis' not in metadata:
                        metadata['provided_apis'] = []
                    metadata['provided_apis'].append({
                        'group': prop_value.get('group'),
                        'version': prop_value.get('version'), 
                        'kind': prop_value.get('kind')
                    })
                    
                elif prop_type == 'olm.gvk.required':
                    # Required APIs
                    if 'required_apis' not in metadata:
                        metadata['required_apis'] = []
                    metadata['required_apis'].append({
                        'group': prop_value.get('group'),
                        'version': prop_value.get('version'),
                        'kind': prop_value.get('kind')
                    })
            
            # Clean up empty sections
            if not metadata['dependencies']:
                del metadata['dependencies']
            if not metadata['related_images']:
                del metadata['related_images']
            if not metadata['properties_summary']:
                del metadata['properties_summary']
            if not metadata.get('provided_apis'):
                metadata.pop('provided_apis', None)
            if not metadata.get('required_apis'):
                metadata.pop('required_apis', None)
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error extracting bundle metadata: {e}")
            # Fallback to basic metadata if parsing fails
            return {
                'bundle_name': bundle_item.get('name'),
                'package': bundle_item.get('package'),
                'bundle_image': bundle_item.get('image'),
                'error': f"Failed to parse detailed metadata: {e}",
                'raw_properties_count': len(bundle_item.get('properties', []))
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
        """Extract CSV metadata from bundle data (olm.bundle.object)"""
        try:
            metadata = bundle_data.get('metadata', {})
            spec = bundle_data.get('spec', {})
            
            return {
                'name': metadata.get('name'),
                'namespace': metadata.get('namespace'),
                'display_name': spec.get('displayName'),
                'description': spec.get('description'),
                'version': spec.get('version'),
                'provider': spec.get('provider', {}).get('name'),
                'maturity': spec.get('maturity'),
                'keywords': spec.get('keywords', []),
                'maintainers': spec.get('maintainers', []),
                'links': spec.get('links', []),
                'icon': spec.get('icon', [{}])[0] if spec.get('icon') else {}
            }
        except Exception as e:
            logger.debug(f"Error extracting CSV metadata: {e}")
            return {}
    
    def _extract_csv_from_metadata(self, csv_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CSV metadata from olm.csv.metadata property"""
        try:
            return {
                'display_name': csv_metadata.get('displayName'),
                'description': csv_metadata.get('description'),
                'version': csv_metadata.get('version'),
                'provider': csv_metadata.get('provider', {}).get('name') if csv_metadata.get('provider') else None,
                'maturity': csv_metadata.get('maturity'),
                'keywords': csv_metadata.get('keywords', []),
                'maintainers': csv_metadata.get('maintainers', []),
                'links': csv_metadata.get('links', []),
                'annotations': csv_metadata.get('annotations', {}),
                'labels': csv_metadata.get('labels', {}),
                'capabilities': csv_metadata.get('annotations', {}).get('capabilities'),
                'categories': csv_metadata.get('annotations', {}).get('categories'),
                'container_image': csv_metadata.get('annotations', {}).get('containerImage'),
                'repository': csv_metadata.get('annotations', {}).get('repository'),
                'created_at': csv_metadata.get('annotations', {}).get('createdAt')
            }
        except Exception as e:
            logger.debug(f"Error extracting CSV from metadata: {e}")
            return {}
    
    def _extract_webhook_info(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract webhook information from bundle spec"""
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
