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

{{- /*
Secrets: each workload reads only its own k8s Secret (see values.yaml), so a compromised pod
exposes only its own keys. The shared secrets.existingSecret is retired and fails the render.
*/}}
{{- define "giano.walletApiSecret" -}}
{{- with .Values.secrets }}{{- if .existingSecret }}
{{- fail "secrets.existingSecret is retired: each workload has its own Secret. Set walletApi.existingSecret (DATABASE_URL) and, with the bundler, bundler.existingSecret (BUNDLER_EXECUTOR_PRIVATE_KEYS only)" }}
{{- end }}{{- end }}
{{- required "walletApi.existingSecret is required (a k8s Secret with DATABASE_URL)" .Values.walletApi.existingSecret -}}
{{- end -}}

{{- define "giano.bundlerSecret" -}}
{{- $name := required "bundler.existingSecret is required when bundler.enabled (a k8s Secret with BUNDLER_EXECUTOR_PRIVATE_KEYS)" .Values.bundler.existingSecret -}}
{{- if eq $name .Values.walletApi.existingSecret }}
{{- fail "bundler.existingSecret must not be walletApi.existingSecret: wallet-api loads its whole Secret, so it would receive the executor keys" }}
{{- end }}
{{- $name -}}
{{- end -}}
