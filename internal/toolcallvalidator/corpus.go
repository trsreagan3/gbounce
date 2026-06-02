// Package toolcallvalidator — hallucinated-tool-call validator (iam-jit
// task #729 / BUILD-8).
//
// Inspects OUTBOUND agent tool-call REQUEST bodies (MCP / OpenAI /
// Anthropic shapes) and reports calls whose name + arguments don't
// match any schema in the corpus.
//
// Rule set + corpus are kept in lock-step with the Python
// implementation at iam-roles/src/iam_jit/tool_call_validator/. A CI
// diff test is filed as follow-up; for v1.0 the two implementations are
// synced manually + audited line-for-line on review (same posture as
// BUILD-9's injectionscan port).
//
// The package is a PURE-FUNCTION library: Validate is the only entry
// point + has no side effects. Callers wire the verdict into their
// audit + request-mutation paths.
package toolcallvalidator

// ToolSchema is one known-tool corpus entry. Mirrors the Python
// ToolSchema dataclass field-for-field.
type ToolSchema struct {
	Name     string
	Shape    string // "mcp" | "openai" | "anthropic"
	Required []string
	Optional []string
	Source   string
	Note     string
}

// SchemaCorpus is a lookup table of (shape, name) -> ToolSchema.
type SchemaCorpus struct {
	tools []ToolSchema
}

// Lookup returns the matching ToolSchema or nil.
func (c *SchemaCorpus) Lookup(shape, name string) *ToolSchema {
	for i := range c.tools {
		if c.tools[i].Shape == shape && c.tools[i].Name == name {
			return &c.tools[i]
		}
	}
	return nil
}

// HasShape returns true if the corpus contains any tool of the shape.
func (c *SchemaCorpus) HasShape(shape string) bool {
	for i := range c.tools {
		if c.tools[i].Shape == shape {
			return true
		}
	}
	return false
}

// NamesForShape returns all tool names registered for a given shape.
func (c *SchemaCorpus) NamesForShape(shape string) []string {
	out := make([]string, 0, 4)
	for i := range c.tools {
		if c.tools[i].Shape == shape {
			out = append(out, c.tools[i].Name)
		}
	}
	return out
}

// DefaultCorpus returns the baked-in MCP + OpenAI + Anthropic corpus.
// Entries CITE their source in the Source field per
// [[ibounce-honest-positioning]] honesty bar.
//
// Lock-step with iam-roles/src/iam_jit/tool_call_validator/corpus.py.
func DefaultCorpus() SchemaCorpus {
	return SchemaCorpus{tools: defaultTools}
}

// MergeCorpus produces a new corpus that overlays operator-supplied
// tools onto the defaults. Operator entries WIN on (shape, name)
// collision — mirrors the Python load_corpus merge order.
func MergeCorpus(operator []ToolSchema) SchemaCorpus {
	if len(operator) == 0 {
		return DefaultCorpus()
	}
	opKey := func(t ToolSchema) string { return t.Shape + "::" + t.Name }
	overlaid := make(map[string]bool, len(operator))
	for _, t := range operator {
		overlaid[opKey(t)] = true
	}
	merged := make([]ToolSchema, 0, len(defaultTools)+len(operator))
	for _, t := range defaultTools {
		if overlaid[opKey(t)] {
			continue
		}
		merged = append(merged, t)
	}
	merged = append(merged, operator...)
	return SchemaCorpus{tools: merged}
}

// --------------------------------------------------------------------
// Baked-in tools — MCP standard methods.
// CITED in `Source` field per [[ibounce-honest-positioning]].
// --------------------------------------------------------------------

var defaultTools = []ToolSchema{
	// MCP — drawn from modelcontextprotocol.io/specification.
	{
		Name:     "tools/list",
		Shape:    "mcp",
		Optional: []string{"cursor"},
		Source:   "modelcontextprotocol.io/specification (tools/list)",
		Note:     "List tools available on the MCP server",
	},
	{
		Name:     "tools/call",
		Shape:    "mcp",
		Required: []string{"name"},
		Optional: []string{"arguments"},
		Source:   "modelcontextprotocol.io/specification (tools/call)",
		Note:     "Invoke a named tool",
	},
	{
		Name:     "resources/list",
		Shape:    "mcp",
		Optional: []string{"cursor"},
		Source:   "modelcontextprotocol.io/specification (resources/list)",
		Note:     "List resources",
	},
	{
		Name:     "resources/read",
		Shape:    "mcp",
		Required: []string{"uri"},
		Source:   "modelcontextprotocol.io/specification (resources/read)",
		Note:     "Read a resource by URI",
	},
	{
		Name:     "prompts/list",
		Shape:    "mcp",
		Optional: []string{"cursor"},
		Source:   "modelcontextprotocol.io/specification (prompts/list)",
		Note:     "List prompts",
	},
	{
		Name:     "prompts/get",
		Shape:    "mcp",
		Required: []string{"name"},
		Optional: []string{"arguments"},
		Source:   "modelcontextprotocol.io/specification (prompts/get)",
		Note:     "Get a prompt by name",
	},
	{
		Name:     "initialize",
		Shape:    "mcp",
		Required: []string{"protocolVersion", "capabilities"},
		Optional: []string{"clientInfo"},
		Source:   "modelcontextprotocol.io/specification (initialize)",
		Note:     "MCP session initialize",
	},
	{
		Name:   "ping",
		Shape:  "mcp",
		Source: "modelcontextprotocol.io/specification (ping)",
		Note:   "Liveness check",
	},

	// OpenAI — drawn from platform.openai.com/docs/assistants/tools.
	{
		Name:   "code_interpreter",
		Shape:  "openai",
		Source: "platform.openai.com/docs/assistants/tools/code-interpreter",
		Note:   "OpenAI code-interpreter built-in tool",
	},
	{
		Name:     "file_search",
		Shape:    "openai",
		Optional: []string{"queries", "max_num_results"},
		Source:   "platform.openai.com/docs/assistants/tools/file-search",
		Note:     "OpenAI file-search built-in tool",
	},
	{
		Name:     "web_search",
		Shape:    "openai",
		Required: []string{"query"},
		Optional: []string{"search_context_size"},
		Source:   "platform.openai.com/docs/guides/tools-web-search",
		Note:     "OpenAI web-search built-in tool",
	},
	{
		Name:     "image_generation",
		Shape:    "openai",
		Required: []string{"prompt"},
		Optional: []string{"size", "quality"},
		Source:   "platform.openai.com/docs/guides/tools-image-generation",
		Note:     "OpenAI image-generation tool",
	},

	// Anthropic — drawn from docs.anthropic.com/en/docs/build-with-claude/tool-use.
	{
		Name:     "computer",
		Shape:    "anthropic",
		Required: []string{"action"},
		Optional: []string{"coordinate", "text", "duration"},
		Source:   "docs.anthropic.com/en/docs/build-with-claude/computer-use",
		Note:     "Anthropic computer-use tool",
	},
	{
		Name:     "text_editor",
		Shape:    "anthropic",
		Required: []string{"command", "path"},
		Optional: []string{"file_text", "insert_line", "new_str", "old_str", "view_range"},
		Source:   "docs.anthropic.com/en/docs/build-with-claude/tool-use/text-editor-tool",
		Note:     "Anthropic text-editor tool",
	},
	{
		Name:     "bash",
		Shape:    "anthropic",
		Required: []string{"command"},
		Optional: []string{"restart"},
		Source:   "docs.anthropic.com/en/docs/build-with-claude/tool-use/bash-tool",
		Note:     "Anthropic bash tool",
	},
	{
		Name:     "web_search",
		Shape:    "anthropic",
		Required: []string{"query"},
		Optional: []string{"max_uses"},
		Source:   "docs.anthropic.com/en/docs/build-with-claude/tool-use/web-search-tool",
		Note:     "Anthropic web-search tool",
	},
}
