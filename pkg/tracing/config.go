package tracing

// Config holds tracing settings loaded from .cloop/config.yaml under the
// "tracing" key. All fields are optional; when Enabled is false (default) the
// no-op tracer is used and no network connections are made.
type Config struct {
	// Enabled activates OTLP trace export. Default: false.
	Enabled bool `yaml:"enabled,omitempty"`
	// Endpoint is the OTLP HTTP receiver URL, e.g. "http://localhost:4318".
	// The exporter uses the /v1/traces path automatically.
	// Required when Enabled is true; ignored otherwise.
	Endpoint string `yaml:"endpoint,omitempty"`
	// ServiceName is reported as the OTel service.name resource attribute.
	// Defaults to "cloop".
	ServiceName string `yaml:"service_name,omitempty"`
}
