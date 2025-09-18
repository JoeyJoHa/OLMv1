# RBAC Manager Test Suite

This directory contains comprehensive test suites for the RBAC Manager tool functionality. The test suites are well-structured to ensure maintainability and reliability.

## Test Files

### `test_catalogd.py`

Tests catalogd functionality including:

- Authentication and port-forwarding
- Catalog listing and selection (new `list-catalogs` subcommand)
- Package, channel, and version queries
- Config generation with `--generate-config` flag
- Real cluster data extraction and placeholder fallback
- Config file output to stdout and files
- Error handling and edge cases
- Output formatting and truncation handling

**Test Structure:**

- **Helper Pattern**: Test methods use `_run_catalogd_test` helper for consistency
- **Uniform Output**: All tests use `_print_test_status` for consistent formatting
- **Maintainable Structure**: Success conditions are clearly defined and reusable

### `test_opm.py`

Tests OPM functionality including:

- Bundle image processing and metadata extraction
- RBAC generation (Helm values and YAML manifests)
- Config file functionality with `--config` flag
- Clean YAML formatting for Helm output
- Channel placeholder and guidance comments
- Config validation and error handling
- Permission optimization logic validation
- Permission scenario handling (cluster-only, namespace-only, both, none)
- Output formatting and file generation
- Error handling and edge cases

**Test Structure:**

- **Loop-Based Execution**: `run_all_tests` uses efficient loop structure
- **Modular Design**: Uses existing `get_available_tests` and `run_specific_test` methods
- **Clean Implementation**: Streamlined test execution logic
- **Easy Extension**: Adding new tests only requires updating `get_available_tests`

### `test_workflow.py`

Tests complete end-to-end workflow including:

- **Complete Workflow:** `catalogd --generate-config` → `opm --config`
- Real cluster authentication and data extraction
- YAML and Helm workflow validation
- Config file generation and consumption
- Parameter discovery from live cluster
- Cross-command integration testing
- Error handling across the complete workflow

## Running Tests

### Prerequisites

1. **Python Environment**: Ensure Python 3.7+ is available
2. **Dependencies**: Install required packages from `requirements.txt`
3. **Working Directory**: Run tests from the `tools/rbac-manager/` directory

```bash
cd tools/rbac-manager/

# Set environment variables
export OPENSHIFT_URL="https://api.your-cluster.com:6443"
export TOKEN="your-openshift-token"

# Run catalogd tests (requires cluster authentication)
python3 tests/test_catalogd.py

# Run OPM tests (no authentication required)
python3 tests/test_opm.py

# Run complete workflow tests (requires cluster authentication)
python3 tests/test_workflow.py
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

- ✅ Cluster catalog listing (`list-catalogs` subcommand)
- ✅ Package discovery and filtering
- ✅ Channel and version queries
- ✅ Authentication handling
- ✅ Config template generation (`--generate-config`)
- ✅ Config generation with real cluster data
- ✅ Config file output (stdout and file modes)
- ✅ Error scenarios and edge cases
- ✅ Output formatting validation
- ✅ Consistent test execution patterns with helper methods
- ✅ Clean test structure across all test methods

### OPM Test Coverage

- ✅ Bundle image processing
- ✅ YAML manifest generation
- ✅ Helm values generation
- ✅ Config file functionality (`--config` flag)
- ✅ Clean YAML formatting
- ✅ Channel placeholder and guidance
- ✅ Config validation and error handling
- ✅ RBAC component analysis
- ✅ Permission optimization validation
- ✅ Permission scenario handling
- ✅ Output directory functionality
- ✅ Error handling and validation
- ✅ Efficient loop-based test execution
- ✅ Consistent patterns using existing infrastructure
- ✅ Maintainable centralized test execution

### Complete Workflow Test Coverage

- ✅ **End-to-end workflow:** `catalogd --generate-config` → `opm --config`
- ✅ **Real cluster integration:** Live data extraction and validation
- ✅ **YAML workflow:** Config generation and YAML manifest creation
- ✅ **Helm workflow:** Config generation and Helm values creation
- ✅ **Parameter discovery:** Automatic test parameter discovery from cluster
- ✅ **Config validation:** Invalid config handling across commands
- ✅ **Cross-command integration:** Seamless data flow between commands

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
- `workflow_test_results_YYYYMMDD_HHMMSS.json`

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions step
- name: Run RBAC Manager Tests
  run: |
    cd tools/rbac-manager
    
    # Run OPM tests (no cluster required)
    python3 tests/test_opm.py
    
    # Run cluster-dependent tests if secrets available
    if [[ -n "${{ secrets.OPENSHIFT_URL }}" ]]; then
      python3 tests/test_catalogd.py
      python3 tests/test_workflow.py
    fi
  env:
    OPENSHIFT_URL: ${{ secrets.OPENSHIFT_URL }}
    TOKEN: ${{ secrets.OPENSHIFT_TOKEN }}
```

## Test Development

### Adding New Tests

1. **Catalogd Tests**: Add methods to `CatalogdTestSuite` class
2. **OPM Tests**: Add methods to `OPMTestSuite` class
3. **Workflow Tests**: Add methods to `WorkflowTestSuite` class
4. **Follow Patterns**: Use existing test methods as templates
5. **Update Coverage**: Add new tests to `run_all_tests()` method

**Benefits of Structured Testing:**

- ✅ **Consistent Output**: All tests use same formatting
- ✅ **Clean Implementation**: Streamlined execution logic  
- ✅ **Easy Maintenance**: Changes to test infrastructure affect all tests
- ✅ **Clear Structure**: Success conditions clearly separated

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

# OPM tests
from tests.test_opm import OPMTestSuite
suite = OPMTestSuite()
result = suite.test_bundle_processing("test", "bundle-image-url")
print(result)

# Workflow tests (requires authentication)
from tests.test_workflow import WorkflowTestSuite
import os
suite = WorkflowTestSuite(
    openshift_url=os.getenv("OPENSHIFT_URL"),
    openshift_token=os.getenv("TOKEN")
)
result = suite.test_complete_yaml_workflow()
print(result)
```
