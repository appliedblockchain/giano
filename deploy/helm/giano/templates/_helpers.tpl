{{- define "giano.tag" -}}
{{- .Values.global.imageTag | default .Chart.AppVersion -}}
{{- end -}}

{{- define "giano.image" -}}
{{- $registry := .root.Values.global.imageRegistry -}}
{{- printf "%s/%s:%s" $registry .name (include "giano.tag" .root) -}}
{{- end -}}

{{- define "giano.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "giano.expectedOrigins" -}}
{{- join "," .Values.config.expectedOrigins -}}
{{- end -}}
