# Project Structure

This document describes the organization and structure of the OLMv1 repository following git and project best practices.

## Repository Overview

The OLMv1 repository is organized following modern software development best practices, with clear separation of concerns and logical grouping of related components.

## Directory Structure

```tree
OLMv1/
├── .github/                    # GitHub-specific configuration
│   ├── workflows/             # GitHub Actions CI/CD workflows
│   │   ├── ci.yml            # Continuous Integration pipeline
│   │   └── release.yml       # Release automation
│   ├── ISSUE_TEMPLATE/       # Issue templates
│   │   ├── bug_report.md     # Bug report template
│   │   └── feature_request.md # Feature request template
│   ├── PULL_REQUEST_TEMPLATE.md # Pull request template
│   └── markdown-link-check-config.json # Link checker config
│
├── docs/                      # Project documentation
│   ├── API.md                # API reference documentation
│   ├── DEPLOYMENT.md         # Deployment instructions
│   └── PROJECT_STRUCTURE.md  # This file
│
├── examples/                  # Example configurations and use cases
│   ├── bundle/               # Example bundle files
│   │   ├── ClusterServiceVersion.json
│   │   ├── CustomResourceDefinition.json
│   │   └── Service.json
│   ├── values/               # Example Helm values files
│   │   └── values-quay-operator.yaml
│   └── yamls/                # Example Kubernetes YAML files
│       ├── 00-namespace.yaml
│       ├── 01-serviceaccount.yaml
│       ├── 02-clusterrole.yaml
│       ├── 03-clusterrolebinding.yaml
│       └── 04-clusterextension.yaml
│
├── helm/                      # Helm chart for OLMv1 deployment
│   ├── Chart.yaml            # Helm chart metadata
│   ├── values.yaml           # Default values
│   └── templates/            # Helm templates
│       ├── _helpers.tpl      # Template helpers
│       ├── clusterextension.yaml
│       ├── clusterrole.yaml
│       ├── NOTES.txt         # Post-install notes
│       ├── role.yaml
│       └── serviceaccount.yaml
│
├── templates/                 # Kubernetes resource templates
│   ├── CustomRoles/          # Custom RBAC templates
│   │   ├── 00-rolebinding.yaml
│   │   ├── 01-clusterrole.yaml
│   │   └── 02-clusterrolebinding.yaml
│   └── OLMv1 Resources/      # Core OLMv1 resource templates
│       ├── 01-clustercatalog.yaml
│       └── 02-clusterextension.yaml
│
├── tools/                     # Development and management tools
│   └── rbac-manager/         # RBAC Manager tool
│       ├── libs/             # Python library modules
│       │   ├── bundle_processor.py
│       │   ├── catalog_query.py
│       │   ├── cli_interface.py
│       │   ├── config_manager.py
│       │   ├── core_utils.py
│       │   ├── data_models.py
│       │   ├── opm_query.py
│       │   ├── rbac_application.py
│       │   └── rbac_converter.py
│       ├── rbac_manager.py   # Main entry point
│       └── requirements.txt  # Python dependencies
│
├── config/                    # Configuration files (future use)
├── scripts/                   # Utility scripts (future use)
├── tests/                     # Test files (future use)
├── workflows/                 # Workflow definitions (future use)
│
├── .gitignore                # Git ignore patterns
├── .yamllint.yml             # YAML linting configuration
├── CHANGELOG.md              # Project changelog
├── CONTRIBUTING.md           # Contribution guidelines
├── LICENSE                   # MIT license
└── README.md                 # Main project documentation
```

## Directory Purposes

### Core Directories

#### `.github/`

Contains GitHub-specific configuration files:

- **workflows/**: GitHub Actions CI/CD pipeline definitions
- **ISSUE_TEMPLATE/**: Templates for standardized issue reporting
- **PULL_REQUEST_TEMPLATE.md**: Template for pull request descriptions
- **markdown-link-check-config.json**: Configuration for link validation

#### `docs/`

Comprehensive project documentation:

- **API.md**: Complete API reference for all components
- **DEPLOYMENT.md**: Step-by-step deployment instructions
- **PROJECT_STRUCTURE.md**: This documentation file

#### `examples/`

Real-world examples and sample configurations:

- **bundle/**: Example operator bundle files
- **values/**: Sample Helm values files for different operators
- **yamls/**: Complete Kubernetes resource examples

#### `helm/`

Production-ready Helm chart for OLMv1 deployment:

- **Chart.yaml**: Chart metadata and version information
- **values.yaml**: Default configuration values
- **templates/**: Kubernetes resource templates with Helm templating

#### `templates/`

Standalone Kubernetes resource templates:

- **CustomRoles/**: RBAC templates for custom roles
- **OLMv1 Resources/**: Core OLMv1 resource definitions

#### `tools/`

Development and operational tools:

- **rbac-manager/**: Complete RBAC management tool with modular architecture

### Future Directories

#### `config/`

Reserved for configuration files and settings that may be needed for different deployment scenarios.

#### `scripts/`

Reserved for utility scripts such as:

- Installation scripts
- Migration utilities
- Development helpers

#### `tests/`

Reserved for comprehensive test suites:

- Unit tests
- Integration tests
- End-to-end tests

#### `workflows/`

Reserved for workflow definitions beyond GitHub Actions, such as:

- Argo Workflows
- Tekton Pipelines
- Custom automation workflows

## File Naming Conventions

### General Conventions

- **Lowercase with hyphens**: Use kebab-case for file and directory names
- **Descriptive names**: Names should clearly indicate the file's purpose
- **Consistent extensions**: Use standard extensions (`.md`, `.yaml`, `.py`, etc.)

### Specific Patterns

- **Documentation**: `UPPERCASE.md` for root-level docs, `lowercase.md` for subdirectory docs
- **YAML files**: Use `.yaml` extension consistently
- **Python files**: Use `snake_case.py` naming
- **Templates**: Number prefixes for ordering (e.g., `01-serviceaccount.yaml`)

## Architecture Principles

### Separation of Concerns

Each directory has a specific, well-defined purpose:

- **Source code** in `tools/`
- **Documentation** in `docs/`
- **Examples** in `examples/`
- **Deployment artifacts** in `helm/` and `templates/`
- **CI/CD configuration** in `.github/`

### Modularity

The project is organized to support:

- **Independent development** of different components
- **Selective deployment** of specific parts
- **Easy maintenance** and updates
- **Clear testing boundaries**

### Scalability

The structure supports growth:

- **New tools** can be added to `tools/`
- **Additional documentation** fits naturally in `docs/`
- **More examples** can be organized in `examples/`
- **Extended CI/CD** workflows in `.github/workflows/`

## Development Workflow

### Working with the Structure

1. **Adding new features**: Place code in appropriate `tools/` subdirectory
2. **Updating documentation**: Use `docs/` for comprehensive docs, inline comments for code
3. **Adding examples**: Place in `examples/` with clear naming and documentation
4. **Modifying deployment**: Update `helm/` chart and `templates/` as needed
5. **CI/CD changes**: Modify `.github/workflows/` files

### Best Practices

1. **Keep related files together**: Group by functionality, not file type
2. **Use clear naming**: Names should be self-documenting
3. **Maintain consistency**: Follow established patterns
4. **Document changes**: Update relevant documentation when making changes
5. **Test thoroughly**: Ensure changes work across different scenarios

## Git Workflow

### Branch Structure

- **main**: Production-ready code
- **develop**: Integration branch for new features
- **feature/***: Individual feature branches
- **hotfix/***: Critical bug fixes
- **release/***: Release preparation branches

### Commit Conventions

Follow conventional commit format:

```tree
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### File Management

- **Add new files**: Ensure they fit the established structure
- **Move files**: Update all references and documentation
- **Delete files**: Clean up related references and update gitignore if needed

## Quality Assurance

### Automated Checks

The CI/CD pipeline validates:

- **Code quality**: Linting and formatting
- **Documentation**: Link checking and consistency
- **Security**: Vulnerability scanning
- **Functionality**: Automated testing

### Manual Reviews

Pull requests should verify:

- **Structure compliance**: Files in correct locations
- **Naming consistency**: Following established conventions
- **Documentation updates**: Keeping docs synchronized
- **Example accuracy**: Ensuring examples work as described

## Migration Guide

### From Previous Structure

If migrating from an older structure:

1. **Move tools**: `hack/tools/` → `tools/`
2. **Reorganize docs**: Scattered docs → `docs/`
3. **Update paths**: Fix all references to moved files
4. **Test thoroughly**: Ensure all functionality still works

### Future Changes

When the structure evolves:

1. **Update this documentation**
2. **Provide migration instructions**
3. **Maintain backward compatibility** where possible
4. **Communicate changes** clearly to contributors

This structure provides a solid foundation for the OLMv1 project while remaining flexible enough to accommodate future growth and changes.

