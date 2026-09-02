{{- define "keycensus.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "keycensus.fullname" -}}
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

{{- define "keycensus.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "keycensus.labels" -}}
helm.sh/chart: {{ include "keycensus.chart" . }}
{{ include "keycensus.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "keycensus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keycensus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "keycensus.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "keycensus.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "keycensus.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{- define "keycensus.configMapName" -}}
{{- default (include "keycensus.fullname" .) .Values.existingConfigMap }}
{{- end }}

{{/* env, envFrom, volumes and mounts shared by the Deployment and the CronJob */}}
{{- define "keycensus.env" -}}
- name: KEYCENSUS_CONFIG
  value: /config/keycensus.yml
{{- range .Values.extraEnv }}
- {{ toYaml . | nindent 2 | trim }}
{{- end }}
{{- end }}

{{- define "keycensus.envFrom" -}}
{{- if .Values.existingSecret }}
- secretRef:
    name: {{ .Values.existingSecret }}
{{- end }}
{{- range .Values.extraEnvFrom }}
- {{ toYaml . | nindent 2 | trim }}
{{- end }}
{{- end }}

{{- define "keycensus.volumes" -}}
- name: config
  configMap:
    name: {{ include "keycensus.configMapName" . }}
- name: out
  emptyDir: {}
- name: tmp
  emptyDir: {}
{{- range .Values.extraVolumes }}
- {{ toYaml . | nindent 2 | trim }}
{{- end }}
{{- end }}

{{- define "keycensus.volumeMounts" -}}
- name: config
  mountPath: /config
  readOnly: true
- name: out
  mountPath: /out
- name: tmp
  mountPath: /tmp
{{- range .Values.extraVolumeMounts }}
- {{ toYaml . | nindent 2 | trim }}
{{- end }}
{{- end }}
