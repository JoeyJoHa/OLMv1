"""
Test file demonstrating the improvements made to RBAC Manager

This file shows how the refactored code can be tested with dependency injection.
"""

import pytest
from unittest.mock import Mock, patch

# Import the refactored components
from rbac_manager.libs.main_app import RBACManager, create_rbac_manager
from rbac_manager.libs.core.constants import KubernetesConstants, ErrorMessages
from rbac_manager.libs.core.utils import handle_ssl_error
from rbac_manager.libs.core.exceptions import AuthenticationError, CatalogdError
from rbac_manager.libs.opm.base_generator import PermissionStrategy, PermissionAnalysis


class TestDependencyInjection:
    """Test dependency injection improvements"""
    
    def test_rbac_manager_with_mocked_dependencies(self):
        """Test RBACManager with injected mock dependencies"""
        # Arrange
        mock_auth = Mock()
        mock_config = Mock()
        mock_bundle = Mock()
        mock_help = Mock()
        
        mock_auth.configure_auth.return_value = True
        mock_auth.get_kubernetes_clients.return_value = (Mock(), Mock(), Mock())
        
        # Act
        rbac_manager = RBACManager(
            auth_provider=mock_auth,
            config_provider=mock_config,
            bundle_provider=mock_bundle,
            help_provider=mock_help
        )
        
        result = rbac_manager.configure_authentication("https://api.cluster.local", "token123")
        
        # Assert
        assert result is True
        mock_auth.configure_auth.assert_called_once_with("https://api.cluster.local", "token123")
    
    def test_factory_function(self):
        """Test the factory function creates RBACManager with defaults"""
        # Act
        rbac_manager = create_rbac_manager(skip_tls=True, debug=True)
        
        # Assert
        assert rbac_manager is not None
        assert rbac_manager.skip_tls is True
        assert rbac_manager.debug is True


class TestConstants:
    """Test constants usage"""
    
    def test_kubernetes_constants(self):
        """Test that constants are properly defined"""
        assert KubernetesConstants.DEFAULT_NAMESPACE == "default"
        assert KubernetesConstants.OLM_API_GROUP == "olm.operatorframework.io"
        assert KubernetesConstants.RBAC_MANAGER_COMPONENT == "rbac-manager"
    
    def test_error_messages(self):
        """Test that error messages are centralized"""
        assert "SSL certificate verification failed" in ErrorMessages.SSL_CERT_VERIFICATION_FAILED
        assert "OPM binary not found" in ErrorMessages.OPM_BINARY_NOT_FOUND


class TestCentralizedErrorHandling:
    """Test centralized error handling"""
    
    def test_ssl_error_handler_with_cert_error(self):
        """Test SSL error handler with certificate verification error"""
        # Arrange
        mock_error = Exception("certificate verify failed")
        
        # Act & Assert
        with pytest.raises(AuthenticationError) as exc_info:
            handle_ssl_error(mock_error, AuthenticationError)
        
        assert "SSL certificate verification failed" in str(exc_info.value)
    
    def test_ssl_error_handler_with_ssl_error(self):
        """Test SSL error handler with generic SSL error"""
        # Arrange
        mock_error = Exception("SSLError: connection failed")
        
        # Act & Assert
        with pytest.raises(CatalogdError) as exc_info:
            handle_ssl_error(mock_error, CatalogdError)
        
        assert "SSL connection error occurred" in str(exc_info.value)


class TestPermissionAnalysis:
    """Test permission analysis improvements"""
    
    def test_permission_strategy_enum(self):
        """Test permission strategy enumeration"""
        assert PermissionStrategy.BOTH_CLUSTER_AND_NAMESPACE.value == "both_cluster_and_namespace"
        assert PermissionStrategy.CLUSTER_ONLY.value == "cluster_only"
        assert PermissionStrategy.NAMESPACE_ONLY_AS_CLUSTER.value == "namespace_only_as_cluster"
        assert PermissionStrategy.NO_PERMISSIONS.value == "no_permissions"
    
    def test_permission_analysis_structure(self):
        """Test permission analysis named tuple"""
        # Arrange
        analysis = PermissionAnalysis(
            strategy=PermissionStrategy.BOTH_CLUSTER_AND_NAMESPACE,
            has_cluster_permissions=True,
            has_namespace_permissions=True,
            cluster_rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
            namespace_rules=[{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["list"]}]
        )
        
        # Assert
        assert analysis.strategy == PermissionStrategy.BOTH_CLUSTER_AND_NAMESPACE
        assert analysis.has_cluster_permissions is True
        assert analysis.has_namespace_permissions is True
        assert len(analysis.cluster_rules) == 1
        assert len(analysis.namespace_rules) == 1


class TestIntegration:
    """Integration tests showing improvements working together"""
    
    @patch('rbac_manager.libs.core.auth.OpenShiftAuth')
    def test_end_to_end_with_constants_and_error_handling(self, mock_auth_class):
        """Test end-to-end flow using constants and improved error handling"""
        # Arrange
        mock_auth = Mock()
        mock_auth_class.return_value = mock_auth
        mock_auth.configure_auth.return_value = True
        
        # Act
        rbac_manager = create_rbac_manager()
        result = rbac_manager.configure_authentication()
        
        # Assert
        assert result is True
        mock_auth.configure_auth.assert_called_once()


if __name__ == "__main__":
    # Run tests if executed directly
    pytest.main([__file__, "-v"])
