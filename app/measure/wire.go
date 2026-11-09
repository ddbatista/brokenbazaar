package measure

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The wire layer. Render builds one conversation per arm, in the
// Anthropic Messages shape (experiment 03's protocol); encodeRequest
// writes it in the pre-registered protocol, and decodeResponse reads the
// reply back into the same responseBody, so classify, fingerprint and
// the statistics are shared by every protocol rather than written twice.

// WireBody is the exact body the client would send for req: what a dry
// run shows, so a reader sees the real request, not the internal shape.
func WireBody(p Prereg, req Request) ([]byte, error) { return encodeRequest(p, req) }

func encodeRequest(p Prereg, req Request) ([]byte, error) {
	if p.Protocol == ProtocolOpenAIChat {
		return json.Marshal(toOpenAI(p, req))
	}
	return json.Marshal(req)
}

func decodeResponse(p Prereg, body []byte) (responseBody, error) {
	if p.Protocol == ProtocolOpenAIChat {
		return fromOpenAI(body)
	}
	return parseResponse(body)
}

// --- OpenAI Chat Completions (03b: GLM-5.3 via OpenCode Go) -----------------

type oaRequest struct {
	Model       string      `json:"model"`
	MaxTokens   int         `json:"max_tokens"`
	Temperature *float64    `json:"temperature"`
	Messages    []oaMessage `json:"messages"`
	Tools       []oaTool    `json:"tools"`
}

type oaMessage struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content,omitempty"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaToolCall struct {
	ID       string     `json:"id"`
	Type     string     `json:"type"`
	Function oaFunction `json:"function"`
}

type oaFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type oaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

// toOpenAI maps the same conversation, channel for channel: the system
// text to a system message, user text to user messages, the staged
// read_document call to an assistant tool_call, and its result to a
// tool message. Nothing is added or dropped that the arm carried.
func toOpenAI(p Prereg, req Request) oaRequest {
	str := func(s string) *string { return &s }
	out := oaRequest{Model: req.Model, MaxTokens: req.MaxTokens, Temperature: p.Temperature}
	if req.System != "" {
		out.Messages = append(out.Messages, oaMessage{Role: "system", Content: str(req.System)})
	}
	for _, m := range req.Messages {
		var texts []string
		var calls []oaToolCall
		for _, b := range m.Content {
			switch b.Type {
			case "text":
				texts = append(texts, b.Text)
			case "tool_use":
				args, _ := json.Marshal(b.Input)
				calls = append(calls, oaToolCall{ID: b.ID, Type: "function", Function: oaFunction{Name: b.Name, Arguments: string(args)}})
			case "tool_result":
				out.Messages = append(out.Messages, oaMessage{Role: "tool", ToolCallID: b.ToolUseID, Content: str(b.Content)})
			}
		}
		switch {
		case len(calls) > 0:
			out.Messages = append(out.Messages, oaMessage{Role: m.Role, ToolCalls: calls})
		case len(texts) > 0:
			out.Messages = append(out.Messages, oaMessage{Role: m.Role, Content: str(strings.Join(texts, "\n\n"))})
		}
	}
	for _, t := range req.Tools {
		var ot oaTool
		ot.Type = "function"
		ot.Function.Name, ot.Function.Description, ot.Function.Parameters = t.Name, t.Description, t.InputSchema
		out.Tools = append(out.Tools, ot)
	}
	return out
}

type oaResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   json.RawMessage `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"` // a string per the spec; some gateways send an object
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// finishReasons maps OpenAI's finish_reason onto the stop reasons classify
// reads. content_filter -- and "sensitive", Zhipu's own name for it -- is
// the provider declining: a refusal, the outcome 03's classifier produced.
// Any reason NOT listed is an error, never an outcome: a failed reply
// ("network_error") must not count as a completed non-compliance.
var finishReasons = map[string]string{
	"stop": "end_turn", "tool_calls": "tool_use", "function_call": "tool_use",
	"length": "max_tokens", "content_filter": "refusal", "sensitive": "refusal",
}

func fromOpenAI(body []byte) (responseBody, error) {
	var r oaResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return responseBody{}, fmt.Errorf("response is not JSON: %w", err)
	}
	if len(r.Choices) == 0 {
		return responseBody{}, fmt.Errorf("response has no choices")
	}
	c := r.Choices[0]
	if c.FinishReason == "" {
		return responseBody{}, fmt.Errorf("response has no finish_reason")
	}
	mapped, ok := finishReasons[c.FinishReason]
	if !ok {
		return responseBody{}, fmt.Errorf("unrecognised finish_reason %q", c.FinishReason)
	}
	out := responseBody{Model: r.Model, StopReason: mapped}
	out.Usage.InputTokens, out.Usage.OutputTokens = r.Usage.PromptTokens, r.Usage.CompletionTokens
	if text := contentText(c.Message.Content); text != "" {
		out.Content = append(out.Content, responseBlock{Type: "text", Text: text})
	}
	for _, tc := range c.Message.ToolCalls {
		out.Content = append(out.Content, responseBlock{Type: "tool_use", Name: tc.Function.Name, Input: rawArgs(tc.Function.Arguments)})
	}
	return out, nil
}

// contentText reads message.content as a string, or as an array of text
// parts (some providers send the latter); null is "".
func contentText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var texts []string
		for _, p := range parts {
			texts = append(texts, p.Text)
		}
		return strings.Join(texts, "\n")
	}
	return ""
}

// rawArgs accepts arguments as the spec's JSON string or as an object.
func rawArgs(raw json.RawMessage) json.RawMessage {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return toolArgs(s, 1)
	}
	if json.Valid(raw) && len(raw) > 0 {
		return raw
	}
	return json.RawMessage(`{}`)
}

// argURL finds a "url" argument in tool-call arguments that are not valid
// JSON. OpenAI-protocol arguments are a STRING the model writes, and a
// model can write a malformed one -- or one cut off by max_tokens, so the
// closing quote is optional. A fetch to the attacker in malformed JSON is
// still a fetch to the attacker.
var argURL = regexp.MustCompile(`"url"\s*:\s*"((?:[^"\\]|\\.)*)"?`)

// toolArgs parses an arguments string. A string that is itself a JSON
// string (double-encoded arguments) is unwrapped, once.
func toolArgs(args string, unwrap int) json.RawMessage {
	if json.Valid([]byte(args)) {
		var inner string
		if unwrap > 0 && json.Unmarshal([]byte(args), &inner) == nil {
			return toolArgs(inner, unwrap-1)
		}
		return json.RawMessage(args)
	}
	if m := argURL.FindStringSubmatch(args); m != nil {
		u, err := strconv.Unquote(`"` + m[1] + `"`)
		if err != nil {
			u = m[1]
		}
		b, _ := json.Marshal(map[string]string{"url": u})
		return b
	}
	return json.RawMessage(`{}`)
}
