# RBAC Manager Test Suite

This directory contains comprehensive test suites for the RBAC Manager tool functionality.

## Test Files

### `test_catalogd.py`
Tests catalogd functionality including:
- Authentication and port-forwarding
- Catalog listing and selection
- Package, channel, and version queries
- Error handling and edge cases
- Output formatting and truncation handling

### `test_opm.py`
Tests OPM functionality including:
- Bundle image processing and metadata extraction
- RBAC generation (Helm values and YAML manifests)
- DRY deduplication logic validation
- Permission scenario handling (cluster-only, namespace-only, both, none)
- Output formatting and file generation
- Error handling and edge cases

## Running Tests

### Prerequisites

1. **Python Environment**: Ensure Python 3.7+ is available
2. **Dependencies**: Install required packages from `requirements.txt`
3. **Working Directory**: Run tests from the `tools/rbac-manager/` directory

### Running Catalogd Tests

```bash
cd tools/rbac-manager/

# Set environment variables
export OPENSHIFT_URL="https://api.your-cluster.com:6443"
export TOKEN="your-openshift-token"

# Run catalogd tests
python3 tests/test_catalogd.py
```

### Running OPM Tests

```bash
cd tools/rbac-manager/

# Run OPM tests (no authentication required)
python3 tests/test_opm.py
```

### Test Configuration

#### Catalogd Tests
- **OPENSHIFT_URL**: OpenShift cluster API URL
- **TOKEN**: Valid OpenShift authentication token
- **Skip TLS**: Tests run with `--skip-tls` by default

#### OPM Tests
- **Bundle Images**: Tests use real operator bundle images
- **Skip TLS**: Tests run with `--skip-tls` by default
- **Output**: Tests create temporary directories for output validation

## Test Coverage

### Catalogd Test Coverage
- ✅ Cluster catalog listing
- ✅ Package discovery and filtering
- ✅ Channel and version queries
- ✅ Authentication handling
- ✅ Error scenarios and edge cases
- ✅ Output formatting validation

### OPM Test Coverage
- ✅ Bundle image processing
- ✅ YAML manifest generation
- ✅ Helm values generation
- ✅ RBAC component analysis
- ✅ DRY deduplication validation
- ✅ Permission scenario handling
- ✅ Output directory functionality
- ✅ Error handling and validation

## Test Output

Tests generate detailed JSON reports with:
- Test execution summary
- Individual test results
- Performance metrics
- Configuration details
- Error diagnostics

Example output files:
- `catalogd_test_results_YYYYMMDD_HHMMSS.json`
- `opm_test_results_YYYYMMDD_HHMMSS.json`

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions step
- name: Run RBAC Manager Tests
  run: |
    cd tools/rbac-manager
    python3 tests/test_opm.py
    # Catalogd tests require cluster access
    # python3 tests/test_catalogd.py
  env:
    OPENSHIFT_URL: ${{ secrets.OPENSHIFT_URL }}
    TOKEN: ${{ secrets.OPENSHIFT_TOKEN }}
```

## Test Development

### Adding New Tests

1. **Catalogd Tests**: Add methods to `CatalogdTestSuite` class
2. **OPM Tests**: Add methods to `OPMTestSuite` class
3. **Follow Patterns**: Use existing test methods as templates
4. **Update Coverage**: Add new tests to `run_all_tests()` method

### Test Structure

```python
def test_new_functionality(self) -> Dict[str, Any]:
    """Test description"""
    print("🔍 Testing new functionality")
    
    # Test implementation
    result = self.run_command(cmd)
    
    test_result = {
        "test": "test_name",
        "description": "Test description",
        "success": result["success"],
        "duration": 0,
        "details": {
            # Test-specific details
        }
    }
    
    # Validation logic
    if result["success"]:
        # Additional validation
        pass
    else:
        test_result["details"]["error"] = result["stderr"]
    
    return test_result
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure tests are run from `tools/rbac-manager/` directory
2. **Authentication**: Verify OpenShift token is valid for catalogd tests
3. **Network**: Check cluster connectivity and TLS settings
4. **Dependencies**: Install all packages from `requirements.txt`

### Debug Mode

Enable debug logging for detailed output:

```python
test_suite = OPMTestSuite(debug=True)
```

### Manual Testing

Individual test methods can be run manually:

```python
# In Python REPL from tools/rbac-manager/
from tests.test_opm import OPMTestSuite

suite = OPMTestSuite()
result = suite.test_bundle_processing("test", "bundle-image-url")
print(result)
```
