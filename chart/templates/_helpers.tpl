{{- define "openport-exporter.name" -}}
openport-exporter
{{- end -}}

{{- define "openport-exporter.fullname" -}}
  {{- if .Values.fullnameOverride -}}
    {{- .Values.fullnameOverride | trim -}}
  {{- else -}}
    {{- printf "%s-%s" (include "openport-exporter.name" .) .Release.Name | trunc 63 | trimSuffix "-" | trim -}}
  {{- end -}}
{{- end -}}


{{- define "openport-exporter.labels" -}}
app.kubernetes.io/name: {{ include "openport-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{- define "openport-exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
  {{- if .Values.serviceAccount.name -}}
    {{ .Values.serviceAccount.name }}
  {{- else -}}
    {{ include "openport-exporter.fullname" . }}-sa
  {{- end }}
{{- else -}}
default
{{- end }}
{{- end -}}
