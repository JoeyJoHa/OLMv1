{{/*
Expand the name of the chart.
*/}}
{{- define "operator-olm-v1.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "operator-olm-v1.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "operator-olm-v1.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "operator-olm-v1.labels" -}}
helm.sh/chart: {{ include "operator-olm-v1.chart" . }}
{{ include "operator-olm-v1.selectorLabels" . }}
{{- if .Values.operator.appVersion }}
app.kubernetes.io/version: {{ .Values.operator.appVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "operator-olm-v1.selectorLabels" -}}
app.kubernetes.io/name: {{ .Values.operator.name | default .Release.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Smart naming for service account
If user provides a name, use it as-is; otherwise use generated name with "-installer" suffix
If create: false, user must provide existing resource name
*/}}
{{- define "operator-olm-v1.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
  {{- if .Values.serviceAccount.name }}
    {{- .Values.serviceAccount.name }}
  {{- else }}
    {{- printf "%s-installer" (include "operator-olm-v1.fullname" .) }}
  {{- end }}
{{- else }}
  {{- .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Smart naming for cluster role from permissions structure
If user provides a name, use it as-is; otherwise use generated name with "-installer" suffix
If create: false, user must provide existing resource name
*/}}
{{- define "operator-olm-v1.clusterRoleName" -}}
{{- if and .Values.serviceAccount.bind (index .Values.permissions.clusterRoles 0).create }}
  {{- if (index .Values.permissions.clusterRoles 0).name }}
    {{- (index .Values.permissions.clusterRoles 0).name }}
  {{- else }}
    {{- printf "%s-installer" (include "operator-olm-v1.fullname" .) }}
  {{- end }}
{{- else }}
  {{- (index .Values.permissions.clusterRoles 0).name }}
{{- end }}
{{- end }}

{{/*
Smart naming for role from permissions structure
If user provides a name, use it as-is; otherwise use generated name with "-installer" suffix
If create: false, user must provide existing resource name
*/}}
{{- define "operator-olm-v1.roleName" -}}
{{- if and .Values.serviceAccount.bind (index .Values.permissions.roles 0).create }}
  {{- if (index .Values.permissions.roles 0).name }}
    {{- (index .Values.permissions.roles 0).name }}
  {{- else }}
    {{- printf "%s-installer" (include "operator-olm-v1.fullname" .) }}
  {{- end }}
{{- else }}
  {{- (index .Values.permissions.roles 0).name }}
{{- end }}
{{- end }}

{{/*
Smart naming for cluster extension
If user provides a name, use it as-is; otherwise use release name
*/}}
{{- define "operator-olm-v1.clusterExtensionName" -}}
{{- if .Values.operator.name }}
  {{- .Values.operator.name }}
{{- else }}
  {{- .Release.Name }}
{{- end }}
{{- end }}

{{/*
Additional Resources Template
Renders additional Kubernetes resources defined in values.yaml
*/}}
{{- define "operator-olmv1.additionalResources" -}}
{{- range $resource := .Values.additionalResources }}
---
{{ toYaml $resource | nindent 0 }}
{{- end }}
{{- end }}
