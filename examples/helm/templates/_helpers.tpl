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
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "operator-olm-v1.selectorLabels" -}}
app.kubernetes.io/name: {{ include "operator-olm-v1.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "operator-olm-v1.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "operator-olm-v1.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role to use
*/}}
{{- define "operator-olm-v1.clusterRoleName" -}}
{{- if .Values.clusterRole.create }}
{{- printf "%s-%s" (include "operator-olm-v1.fullname" .) .Values.clusterRole.name }}
{{- else }}
{{- .Values.clusterRole.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role binding to use
*/}}
{{- define "operator-olm-v1.clusterRoleBindingName" -}}
{{- if .Values.clusterRoleBinding.create }}
{{- printf "%s-%s" (include "operator-olm-v1.fullname" .) .Values.clusterRoleBinding.name }}
{{- else }}
{{- .Values.clusterRoleBinding.name }}
{{- end }}
{{- end }}
