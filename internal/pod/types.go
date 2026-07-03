// types.go — typed Go structs that mirror pod.toml v0.1.
//
// These are the canonical client-side representation of a pod definition.
// Optional sections are pointers so callers can distinguish "absent" from
// "set to zero value" (matters for spawn-time decisions like whether to
// apply default budgets vs. explicit zeros).
//
// The struct tags drive BurntSushi/toml decoding via Parse(). The schema
// validation happens separately in Validate() against the canonical JSON
// Schema; these types are not the schema's source of truth.
package pod

// Spec is the top-level pod.toml document.
type Spec struct {
	PodSpecVersion string        `toml:"pod_spec_version"`
	Pod            Identity      `toml:"pod"`
	Runtime        Runtime       `toml:"runtime"`
	Model          *Model        `toml:"model,omitempty"`
	Hardware       *Hardware     `toml:"hardware,omitempty"`
	Dependencies   *Dependencies `toml:"dependencies,omitempty"`
	Context        *Context      `toml:"context,omitempty"`
	Inputs         Inputs        `toml:"inputs,omitempty"`
	Directive      *Directive    `toml:"directive,omitempty"`
	Output         *Output       `toml:"output,omitempty"`
	Budget         *Budget       `toml:"budget,omitempty"`
	Wallet         *Wallet       `toml:"wallet,omitempty"`
	Hooks          *Hooks        `toml:"hooks,omitempty"`
	Marketplace    *Marketplace  `toml:"marketplace,omitempty"`
}

// Identity is the [pod] table — author-facing metadata.
type Identity struct {
	Name        string   `toml:"name"`
	Version     string   `toml:"version"`
	Authors     []string `toml:"authors,omitempty"`
	License     string   `toml:"license,omitempty"`
	Description string   `toml:"description,omitempty"`
	Homepage    string   `toml:"homepage,omitempty"`
	Tags        []string `toml:"tags,omitempty"`
	// LineageID is the 16-byte cross-session salt-lookup key, encoded
	// as a 32-character lowercase hex string. Set once at genesis by
	// `konareef pod init`. Type-C pods may ignore it; Type-D pods
	// require it to resolve lineage-scoped salt material.
	LineageID string `toml:"lineage_id,omitempty"`
}

// Runtime is the [runtime] table — selects which harness to spawn.
type Runtime struct {
	Kind    string `toml:"kind"`
	Version string `toml:"version,omitempty"`
}

// Model is the [model] table — selects the LLM driving the runtime.
// Temperature is a pointer because 0.0 is a valid explicit value
// distinct from "not set".
type Model struct {
	Provider     string                 `toml:"provider"`
	Name         string                 `toml:"name"`
	MaxTokens    int                    `toml:"max_tokens,omitempty"`
	Temperature  *float64               `toml:"temperature,omitempty"`
	ProviderOpts map[string]interface{} `toml:"provider_opts,omitempty"`
}

// Hardware is the [hardware] table — minimum resource requirements.
type Hardware struct {
	CPUCores int    `toml:"cpu_cores,omitempty"`
	Memory   string `toml:"memory,omitempty"`
	Disk     string `toml:"disk,omitempty"`
	GPU      *GPU   `toml:"gpu,omitempty"`
}

// GPU is the [hardware.gpu] sub-table.
type GPU struct {
	Kind    string `toml:"kind"`
	Count   int    `toml:"count"`
	VRAMGiB int    `toml:"vram_gib"`
	Model   string `toml:"model,omitempty"`
}

// Dependencies is the [dependencies] table — system, runtime, and secret
// requirements resolved at spawn time. Secrets are *names only*; values
// come from reef-core's vault.
type Dependencies struct {
	System  []string `toml:"system,omitempty"`
	Runtime []string `toml:"runtime,omitempty"`
	Secrets []string `toml:"secrets,omitempty"`
}

// Context is the [context] table — pre-loaded memory, skills, tools, and
// prompts injected before the directive fires.
type Context struct {
	Memory  []ContextMemory `toml:"memory,omitempty"`
	Skills  []ContextSkill  `toml:"skills,omitempty"`
	Tools   []ContextTool   `toml:"tools,omitempty"`
	Prompts []ContextPrompt `toml:"prompts,omitempty"`
}

// ContextMemory is one [[context.memory]] entry.
type ContextMemory struct {
	Kind     string `toml:"kind"`
	Snapshot string `toml:"snapshot,omitempty"`
	Path     string `toml:"path,omitempty"`
	URL      string `toml:"url,omitempty"`
	Content  string `toml:"content,omitempty"`
}

// ContextSkill is one [[context.skills]] entry.
type ContextSkill struct {
	Source  string `toml:"source"`
	Version string `toml:"version,omitempty"`
}

// ContextTool is one [[context.tools]] entry.
type ContextTool struct {
	Source string                 `toml:"source"`
	Config map[string]interface{} `toml:"config,omitempty"`
}

// ContextPrompt is one [[context.prompts]] entry.
type ContextPrompt struct {
	Role string `toml:"role"`
	Path string `toml:"path"`
}

// Inputs is the [inputs] table — typed parameters callers pass at spawn.
// Maps the input name to its definition.
type Inputs map[string]Input

// Input is one [inputs.<name>] descriptor. v0.1 exposes only the fields
// callers need for prompt rendering and required-input enforcement; type-
// specific constraints (default, min, max, pattern, values) are validated
// at the schema layer and not surfaced through this struct yet.
type Input struct {
	Type        string `toml:"type"`
	Required    bool   `toml:"required,omitempty"`
	Description string `toml:"description,omitempty"`
}

// Directive is the [directive] table — the mission. Exactly one of Task
// or Template must be set; this is enforced by the schema.
type Directive struct {
	Task          string   `toml:"task,omitempty"`
	Template      string   `toml:"template,omitempty"`
	MaxIterations int      `toml:"max_iterations,omitempty"`
	ToolsAllowed  []string `toml:"tools_allowed,omitempty"`
	ToolsDenied   []string `toml:"tools_denied,omitempty"`
}

// Output is the [output] table — success/failure predicates and
// deliverables. Used by reef-core to decide when a pod is "done".
type Output struct {
	Format       string        `toml:"format,omitempty"`
	Success      []Predicate   `toml:"success,omitempty"`
	Failure      []Predicate   `toml:"failure,omitempty"`
	Deliverables []Deliverable `toml:"deliverables,omitempty"`
}

// Predicate is one [[output.success]] or [[output.failure]] entry.
// Kind discriminates which other fields are meaningful (e.g.,
// kind="file_exists" requires Path; kind="min_words" requires Path+Count;
// kind="timeout_seconds" requires Value).
type Predicate struct {
	Kind    string `toml:"kind"`
	Path    string `toml:"path,omitempty"`
	Count   int    `toml:"count,omitempty"`
	Pattern string `toml:"pattern,omitempty"`
	Value   int    `toml:"value,omitempty"`
	Tool    string `toml:"tool,omitempty"`
	Script  string `toml:"script,omitempty"`
}

// Deliverable is one [[output.deliverables]] entry.
type Deliverable struct {
	Path        string `toml:"path"`
	Description string `toml:"description,omitempty"`
	Optional    bool   `toml:"optional,omitempty"`
}

// Budget is the [budget] table — sat-denominated spend caps.
type Budget struct {
	MaxSats        int `toml:"max_sats,omitempty"`
	PerCallCapSats int `toml:"per_call_cap_sats,omitempty"`
	DailyCapSats   int `toml:"daily_cap_sats,omitempty"`
}

// Wallet is the [wallet] table — wallet provisioning strategy. Reuse is
// required when Strategy = "reuse" (enforced by the schema).
type Wallet struct {
	Strategy string `toml:"strategy"`
	Reuse    string `toml:"reuse,omitempty"`
}

// Hooks is the [hooks] table — escape-hatch shell scripts at lifecycle
// points. Marketplace audits should flag any pod that uses these.
type Hooks struct {
	PreSpawn  string `toml:"pre_spawn,omitempty"`
	PostSpawn string `toml:"post_spawn,omitempty"`
	OnSuccess string `toml:"on_success,omitempty"`
	OnFailure string `toml:"on_failure,omitempty"`
}

// Marketplace is the [marketplace] table — discovery + commerce metadata.
type Marketplace struct {
	Listed      bool     `toml:"listed,omitempty"`
	PriceModel  string   `toml:"price_model,omitempty"`
	PriceSats   int      `toml:"price_sats,omitempty"`
	PreviewURL  string   `toml:"preview_url,omitempty"`
	Icon        string   `toml:"icon,omitempty"`
	Screenshots []string `toml:"screenshots,omitempty"`
	Categories  []string `toml:"categories,omitempty"`
}
