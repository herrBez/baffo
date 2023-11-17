package transpile

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	ast "github.com/breml/logstash-config/ast"
)

type Constraints struct {
	Conditions []ast.Condition
}

func (c Constraints) String() {
	transpileConstraint(c)
}

func NewConstraint(_conditions ...ast.Condition) Constraints {
	return Constraints{
		Conditions: _conditions,
	}
}

func NewConstraintLiteral() Constraints {
	return Constraints{
		Conditions: []ast.Condition{},
	}
}

func AddCondToConstraint(c Constraints, cond ast.Condition) Constraints {
	newC := Constraints{
		Conditions: append(c.Conditions, cond),
	}
	return newC
}

type IngestPipeline struct {
	Name                string            `json:"-"`
	Description         string            `json:"description"`
	Processors          []IngestProcessor `json:"processors"`
	OnFailureProcessors []IngestProcessor `json:"on_failure"`
}

func NewIngestPipeline() IngestPipeline {
	return IngestPipeline{
		Description:         "",
		Processors:          []IngestProcessor{},
		OnFailureProcessors: nil,
	}
}

// func processorsArrayToArrayMap(ips []IngestProcessor) []map[string]IngestProcessor {
// 	output := []map[string]IngestProcessor{}

// 	for _, ip := range ips {
// 		output = append(output, ToOutputMap(ip))
// 	}

// 	return output
// }

func MyJsonEncode(v any) ([]byte, error) {
	buf := new(bytes.Buffer)

	e := json.NewEncoder(buf)

	e.SetEscapeHTML(false)

	err := e.Encode(v)

	if err != nil {
		// Panic
		log.Panic().Msg("Something wrong in marshalling")
	}
	return buf.Bytes(), err
}

func ExtractString(b []byte, err error) string {
	if err != nil {
		log.Panic().Msg("Could not marshal")
	}
	return string(b)
}

// Prepend the new If to make sure that the Logstash's original conditions apply first
func AppendIf(origIf *string, newIf *string) *string {
	var resIf *string = nil
	if origIf == nil {
		resIf = newIf
	} else if newIf == nil {
		resIf = origIf
	} else {
		resIf = getStringPointer(fmt.Sprintf("(%s) && (%s)", *newIf, *origIf))
	}
	return resIf
}

func (ingestPipeline IngestPipeline) String() string {

	m := map[string]interface{}{
		"description": ingestPipeline.Description,
		"processors":  ingestPipeline.Processors,
	}
	if ingestPipeline.OnFailureProcessors != nil {
		m["on_failure"] = ingestPipeline.OnFailureProcessors
	}
	buf, err := MyJsonEncode(m)

	if err != nil {
		log.Panic().Msg("Could not marshal")
	}
	return string(buf)
}

type IngestProcessor interface {
	String() string
	IngestProcessorType() string
	WithIf(s *string, append bool) IngestProcessor
	WithTag(s string) IngestProcessor
	WithOnFailure(s []IngestProcessor) IngestProcessor
	WithDescription(s string) IngestProcessor
	// SetTag(string)
}

type CommonFields struct {
	If          *string           `json:"if,omitempty"`
	Tag         *string           `json:"tag,omitempty"`
	OnFailure   []IngestProcessor `json:"on_failure,omitempty"`
	Description *string           `json:"description,omitempty"`
}

type CF interface {
	GetTag() *string
	GetTagOrDefault(string) string
	GetDescription() *string
	GetDescriptionOrDefault(string) string
	GetOnFailure() []IngestProcessor
	GetIf() *string
	GetIfOrDefault(string) string
}

func (cf CommonFields) GetIf() *string {
	return cf.If
}

func (cf CommonFields) GetIfOrDefault(str string) string {
	if cf.If != nil {
		return *cf.If
	} else {
		return str
	}
}

func (cf CommonFields) GetOnFailure() []IngestProcessor {
	return cf.OnFailure
}

func (cf CommonFields) GetTag() *string {
	return cf.Tag
}

func (cf CommonFields) GetTagOrDefault(str string) string {
	if cf.Tag != nil {
		return *cf.Tag
	} else {
		return str
	}
}

func (cf CommonFields) GetDescription() *string {
	return cf.Description
}

func (cf CommonFields) GetDescriptionOrDefault(str string) string {
	if cf.Description != nil {
		return *cf.Description
	} else {
		return str
	}
}

type SetProcessor struct {
	Value            string `json:"value,omitempty"`
	Field            string `json:"field"`
	CopyFrom         string `json:"copy_from,omitempty"`
	Override         bool   `json:"override,omitempty"`
	IgnoreEmptyValue bool   `json:"ignore_empty_value,omitempty"`
	MediaType        string `json:"media_type,omitempty"`
	IgnoreFailure    bool   `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ip SetProcessor) MarshalJSON() ([]byte, error) {
	type SetProcessorAlias SetProcessor
	return MyJsonEncode(
		map[string]SetProcessorAlias{
			ip.IngestProcessorType(): (SetProcessorAlias)(ip),
		},
	)
}

func StringHelper(ip IngestProcessor) string {

	return ExtractString(MyJsonEncode(map[string]interface{}{
		ip.IngestProcessorType(): ip,
	}))
}

func (sp SetProcessor) String() string {
	return StringHelper(sp)
}

func (sp SetProcessor) IngestProcessorType() string {
	return "set"
}

func (sp SetProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp SetProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp SetProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp SetProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

type RemoveProcessor struct {
	Field         *string  `json:"field,omitempty"`
	IgnoreMissing bool     `json:"ignore_missing,omitempty"`
	Keep          []string `json:"keep,omitempty"`
	IgnoreFailure bool     `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ip RemoveProcessor) String() string {
	return StringHelper(ip)
}

func (sp RemoveProcessor) IngestProcessorType() string {
	return "remove"
}

func (sp RemoveProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp RemoveProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp RemoveProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp RemoveProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (ip RemoveProcessor) MarshalJSON() ([]byte, error) {
	type RemoveProcessorAlias RemoveProcessor

	return MyJsonEncode(
		map[string]RemoveProcessorAlias{
			ip.IngestProcessorType(): (RemoveProcessorAlias)(ip),
		},
	)
}

type RenameProcessor struct {
	Field         string `json:"field"`
	TargetField   string `json:"target_field"`
	IgnoreMissing bool   `json:"ignore_missing"`
	IgnoreFailure bool   `json:"ignore_failure,omitempty"`
	CommonFields
}

func (sp RenameProcessor) String() string {
	return StringHelper(sp)
}

func (sp RenameProcessor) IngestProcessorType() string {
	return "rename"
}

func (sp RenameProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp RenameProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp RenameProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp RenameProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (ip RenameProcessor) MarshalJSON() ([]byte, error) {
	type RenameProcessorAlias RenameProcessor

	return MyJsonEncode(
		map[string]RenameProcessorAlias{
			ip.IngestProcessorType(): (RenameProcessorAlias)(ip),
		},
	)
}

// Type for lowercase/uppercase
type CaseProcessor struct {
	Type          string  `json:"-"` // The field is only used internally to distinguish lowercase/uppercase
	Field         string  `json:"field"`
	TargetField   *string `json:"target_field,omitempty"`
	IgnoreMissing bool    `json:"ignore_missing,omitempty"`
	IgnoreFailure bool    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (cp CaseProcessor) String() string {
	return StringHelper(cp)
}

func (cp CaseProcessor) IngestProcessorType() string {
	return cp.Type
}

func (sp CaseProcessor) ToOutputMap() map[string]interface{} {
	return map[string]interface{}{}
}

func (sp CaseProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp CaseProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp CaseProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp CaseProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (ip CaseProcessor) MarshalJSON() ([]byte, error) {
	type CaseProcessorAlias CaseProcessor

	return MyJsonEncode(
		map[string]CaseProcessorAlias{
			ip.IngestProcessorType(): (CaseProcessorAlias)(ip),
		},
	)
}

// Type for lowercase/uppercase
type GrokProcessor struct {
	Field              string            `json:"field,omitempty"`
	Patterns           []string          `json:"patterns,omitempty"`
	PatternDefinitions map[string]string `json:"pattern_definitions,omitempty"`
	ECSCompatibility   string            `json:"ecs_compatibility,omitempty"`
	TraceMatch         bool              `json:"trace_match,omitempty"`
	IgnoreMissing      bool              `json:"ignore_missing,omitempty"`
	IgnoreFailure      bool              `json:"ignore_failure,omitempty"`
	CommonFields
}

func (gp GrokProcessor) String() string {
	return StringHelper(gp)
}

func (gp GrokProcessor) IngestProcessorType() string {
	return "grok"
}

func (sp GrokProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp GrokProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp GrokProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (sp GrokProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (ip GrokProcessor) MarshalJSON() ([]byte, error) {
	type GrokProcessorAlias GrokProcessor

	return MyJsonEncode(
		map[string]GrokProcessorAlias{
			ip.IngestProcessorType(): (GrokProcessorAlias)(ip),
		},
	)
}

type AppendProcessor struct {
	Field           string   `json:"field,omitempty"`
	Value           []string `json:"value,omitempty"`
	AllowDuplicates bool     `json:"allow_duplicates,omitempty"`
	MediaType       *string  `json:"media_type,omitempty"`
	IgnoreFailure   bool     `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap AppendProcessor) String() string {
	return StringHelper(ap)
}

func (ap AppendProcessor) IngestProcessorType() string {
	return "append"
}

func (sp AppendProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (ip AppendProcessor) MarshalJSON() ([]byte, error) {
	type AppendProcessorAlias AppendProcessor

	return MyJsonEncode(
		map[string]AppendProcessorAlias{
			ip.IngestProcessorType(): (AppendProcessorAlias)(ip),
		},
	)
}

func (sp AppendProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp AppendProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp AppendProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

type GsubProcessor struct {
	Field         string  `json:"field,omitempty"`
	Pattern       string  `json:"pattern,omitempty"`
	Replacement   string  `json:"replacement"`
	TargetField   *string `json:"target_field,omitempty"`
	IgnoreMissing bool    `json:"ignore_missing,omitempty"`
	IgnoreFailure bool    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap GsubProcessor) String() string {
	return StringHelper(ap)
}

func (ap GsubProcessor) IngestProcessorType() string {
	return "gsub"
}

func (sp GsubProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp GsubProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp GsubProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp GsubProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (ip GsubProcessor) MarshalJSON() ([]byte, error) {
	type GsubProcessorAlias GsubProcessor

	return MyJsonEncode(
		map[string]GsubProcessorAlias{
			ip.IngestProcessorType(): (GsubProcessorAlias)(ip),
		},
	)
}

type JoinProcessor struct {
	Field         string  `json:"field,omitempty"`
	Separator     string  `json:"separator,omitempty"`
	TargetField   *string `json:"target_field,omitempty"`
	IgnoreMissing bool    `json:"ignore_missing,omitempty"`
	IgnoreFailure bool    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap JoinProcessor) String() string {
	return StringHelper(ap)
}

func (ap JoinProcessor) IngestProcessorType() string {
	return "join"
}

func (sp JoinProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp JoinProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (ip JoinProcessor) MarshalJSON() ([]byte, error) {
	type JoinProcessorAlias JoinProcessor

	return MyJsonEncode(
		map[string]JoinProcessorAlias{
			ip.IngestProcessorType(): (JoinProcessorAlias)(ip),
		},
	)
}

func (sp JoinProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp JoinProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

type KVProcessor struct {
	Field         string   `json:"field,omitempty"`
	FieldSplit    string   `json:"field_split,omitempty"`
	ValueSplit    string   `json:"value_split,omitempty"`
	TargetField   *string  `json:"target_field,omitempty"`
	IncludeKeys   []string `json:"include_keys,omitempty"`
	ExcludeKeys   []string `json:"exclude_keys,omitempty"`
	IgnoreMissing bool     `json:"ignore_missing,omitempty"`
	Prefix        *string  `json:"prefix,omitempty"`
	TrimKey       *string  `json:"trim_key,omitempty"`
	TrimValue     *string  `json:"trim_value,omitempty"`
	StripBrackets bool     `json:"strip_bracket,omitempty"`
	Pattern       string   `json:"patterns,omitempty"`
	IgnoreFailure bool     `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap KVProcessor) String() string {
	return StringHelper(ap)
}

func (ap KVProcessor) IngestProcessorType() string {
	return "kv"
}

func (sp KVProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp KVProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (ip KVProcessor) MarshalJSON() ([]byte, error) {
	type KVProcessorAlias KVProcessor

	return MyJsonEncode(
		map[string]KVProcessorAlias{
			ip.IngestProcessorType(): (KVProcessorAlias)(ip),
		},
	)
}

func (sp KVProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp KVProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

type DissectProcessor struct {
	Field           string  `json:"field,omitempty"`
	Pattern         string  `json:"pattern,omitempty"`
	AppendSeparator *string `json:"append_separator,omitempty"`
	IgnoreMissing   bool    `json:"ignore_missing,omitempty"`
	IgnoreFailure   bool    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap DissectProcessor) String() string {
	return StringHelper(ap)
}

func (ap DissectProcessor) IngestProcessorType() string {
	return "dissect"
}

func (sp DissectProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp DissectProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (ip DissectProcessor) MarshalJSON() ([]byte, error) {
	type DissectProcessorAlias DissectProcessor

	return MyJsonEncode(
		map[string]DissectProcessorAlias{
			ip.IngestProcessorType(): (DissectProcessorAlias)(ip),
		},
	)
}

func (sp DissectProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp DissectProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

type DateProcessor struct {
	Field         string   `json:"field,omitempty"`
	TargetField   *string  `json:"target_field,omitempty"` // Default value @timestamp
	Formats       []string `json:"formats,omitempty"`
	Pattern       string   `json:"patterns,omitempty"`
	Timezone      *string  `json:"timezone,omitempty"`
	Locale        *string  `json:"locale,omitempty"`
	OutputFormat  *string  `json:"output_format,omitempty"` // Default yyyy-MM-dd'T'HH:mm:ss.SSSXXX
	IgnoreMissing bool     `json:"ignore_missing,omitempty"`
	IgnoreFailure bool     `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap DateProcessor) String() string {
	return StringHelper(ap)
}

func (ap DateProcessor) IngestProcessorType() string {
	return "date"
}

func (sp DateProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp DateProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp DateProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (sp DateProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (ip DateProcessor) MarshalJSON() ([]byte, error) {
	type DateProcessorAlias DateProcessor

	return MyJsonEncode(
		map[string]DateProcessorAlias{
			ip.IngestProcessorType(): (DateProcessorAlias)(ip),
		},
	)
}

type DropProcessor struct {
	IgnoreFailure bool `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ip DropProcessor) MarshalJSON() ([]byte, error) {
	type DropProcessorAlias DropProcessor

	return MyJsonEncode(
		map[string]DropProcessorAlias{
			ip.IngestProcessorType(): (DropProcessorAlias)(ip),
		},
	)
}

func (sp DropProcessor) String() string {
	return StringHelper(sp)
}

func (sp DropProcessor) IngestProcessorType() string {
	return "drop"
}

func (sp DropProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp DropProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp DropProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp DropProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

type SplitProcessor struct {
	Field            string  `json:"field"`
	Separator        string  `json:"separator"`
	TargetField      *string `json:"target_field,omitempty"`
	IgnoreMissing    *bool   `json:"ignore_missing,omitempty"`
	PreserveTrailing *bool   `json:"preserve_trailing,omitempty"`
	IgnoreFailure    bool    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap SplitProcessor) String() string {
	return StringHelper(ap)
}

func (ap SplitProcessor) IngestProcessorType() string {
	return "split"
}

func (sp SplitProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp SplitProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (ip SplitProcessor) MarshalJSON() ([]byte, error) {
	type SplitProcessorAlias SplitProcessor

	return MyJsonEncode(
		map[string]SplitProcessorAlias{
			ip.IngestProcessorType(): (SplitProcessorAlias)(ip),
		},
	)
}

func (sp SplitProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp SplitProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

type TrimProcessor struct {
	Field            string  `json:"field"`
	TargetField      *string `json:"target_field,omitempty"`
	IgnoreMissing    *bool   `json:"ignore_missing,omitempty"`
	PreserveTrailing *bool   `json:"preserve_trailing,omitempty"`
	IgnoreFailure    bool    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap TrimProcessor) String() string {
	return StringHelper(ap)
}

func (ap TrimProcessor) IngestProcessorType() string {
	return "trim"
}

func (sp TrimProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp TrimProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp TrimProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp TrimProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (ip TrimProcessor) MarshalJSON() ([]byte, error) {
	type TrimProcessorAlias TrimProcessor

	return MyJsonEncode(
		map[string]TrimProcessorAlias{
			ip.IngestProcessorType(): (TrimProcessorAlias)(ip),
		},
	)
}

type PipelineProcessor struct {
	Pipeline              *IngestPipeline `json:"-"`
	Name                  string          `json:"name"`
	IgnoreMissingPipeline *bool           `json:"ignore_missing_pipeline,omitempty"`
	IgnoreFailure         bool            `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap PipelineProcessor) String() string {
	return StringHelper(ap)
}

func (ap PipelineProcessor) IngestProcessorType() string {
	return "pipeline"
}
func (sp PipelineProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp PipelineProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp PipelineProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp PipelineProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (ip PipelineProcessor) MarshalJSON() ([]byte, error) {
	type PipelineProcessorAlias PipelineProcessor
	return MyJsonEncode(map[string]PipelineProcessorAlias{
		ip.IngestProcessorType(): (PipelineProcessorAlias)(ip),
	})
}

type ScriptProcessor struct {
	Lang          *string                 `json:"lang,omitempty"`
	Id            *string                 `json:"id,omitempty"`
	Source        *string                 `json:"source,omitempty"`
	Params        *map[string]interface{} `json:"params,omitempty"`
	IgnoreFailure bool                    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ap ScriptProcessor) String() string {
	return StringHelper(ap)
}

func (ap ScriptProcessor) IngestProcessorType() string {
	return "script"
}

func (sp ScriptProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp ScriptProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp ScriptProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp ScriptProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (ip ScriptProcessor) MarshalJSON() ([]byte, error) {
	type ScriptProcessorAlias ScriptProcessor

	return MyJsonEncode(
		map[string]ScriptProcessorAlias{
			ip.IngestProcessorType(): (ScriptProcessorAlias)(ip),
		},
	)
}

// Convert Processors Type: integer, long, float, double, string, boolean, ip, and auto
// Convert Logstash Type: integer, integer_eu, float, float_eu, string, boolean
var LogstashConvertToConvertProcessorType = map[string]string{
	"integer":    "integer",
	"integer_eu": "integer",
	"float":      "float",
	"float_eu":   "float_eu",
	"string":     "string",
	"boolean":    "boolean",
}

type ConvertProcessor struct {
	Field         string  `json:"field"`
	TargetField   *string `json:"target_field,omitempty"`
	Type          string  `json:"type"`
	IgnoreMissing *bool   `json:"ignore_missing,omitempty"`
	IgnoreFailure bool    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (sp ConvertProcessor) String() string {
	return StringHelper(sp)
}

func (sp ConvertProcessor) IngestProcessorType() string {
	return "convert"
}

func (sp ConvertProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp ConvertProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp ConvertProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (sp ConvertProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (ip ConvertProcessor) MarshalJSON() ([]byte, error) {
	type ConvertProcessorAlias ConvertProcessor

	return MyJsonEncode(
		map[string]ConvertProcessorAlias{
			ip.IngestProcessorType(): (ConvertProcessorAlias)(ip),
		},
	)
}

type GeoIPProcessor struct {
	Field         string    `json:"field"`
	TargetField   *string   `json:"target_field,omitempty"`
	DatabaseFile  *string   `json:"database_file,omitempty"`
	Properties    *[]string `json:"properties,omitempty"`
	IgnoreMissing *bool     `json:"ignore_missing,omitempty"`
	FirstOnly     *bool     `json:"first_only,omitempty"`
	IgnoreFailure bool      `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ip GeoIPProcessor) MarshalJSON() ([]byte, error) {
	type GeoIPProcessorAlias GeoIPProcessor

	return MyJsonEncode(
		map[string]GeoIPProcessorAlias{
			ip.IngestProcessorType(): (GeoIPProcessorAlias)(ip),
		},
	)
}

func (sp GeoIPProcessor) String() string {
	return StringHelper(sp)
}

func (sp GeoIPProcessor) IngestProcessorType() string {
	return "geoip"
}

func (sp GeoIPProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp GeoIPProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (sp GeoIPProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp GeoIPProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

type UserAgentProcessor struct {
	Field             string    `json:"field"`
	TargetField       *string   `json:"target_field,omitempty"`
	RegexFile         *string   `json:"regex_file,omitempty"`
	Properties        *[]string `json:"properties,omitempty"`
	ExtractDeviceType string    `json:"extract_deviceType,omitempty"`
	IgnoreMissing     *bool     `json:"ignore_missing,omitempty"`
	IgnoreFailure     bool      `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ip UserAgentProcessor) MarshalJSON() ([]byte, error) {
	type UserAgentProcessorAlias UserAgentProcessor

	return MyJsonEncode(
		map[string]UserAgentProcessorAlias{
			ip.IngestProcessorType(): (UserAgentProcessorAlias)(ip),
		},
	)
}

func (sp UserAgentProcessor) String() string {
	return StringHelper(sp)
}

func (sp UserAgentProcessor) IngestProcessorType() string {
	return "user_agent"
}

func (sp UserAgentProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp UserAgentProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp UserAgentProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}

func (sp UserAgentProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

type URLDecodeProcessor struct {
	Field         string  `json:"field"`
	TargetField   *string `json:"target_field,omitempty"`
	IgnoreMissing *bool   `json:"ignore_missing,omitempty"`
	IgnoreFailure bool    `json:"ignore_failure,omitempty"`
	CommonFields
}

func (ip URLDecodeProcessor) MarshalJSON() ([]byte, error) {
	type URLDecodeProcessorAlias URLDecodeProcessor

	return MyJsonEncode(
		map[string]URLDecodeProcessorAlias{
			ip.IngestProcessorType(): (URLDecodeProcessorAlias)(ip),
		},
	)
}

func (sp URLDecodeProcessor) String() string {
	return StringHelper(sp)
}

func (sp URLDecodeProcessor) IngestProcessorType() string {
	return "user_agent"
}

func (sp URLDecodeProcessor) WithIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp URLDecodeProcessor) WithOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp URLDecodeProcessor) WithTag(tag string) IngestProcessor {
	sp.Tag = getStringPointer(tag)
	return sp
}

func (sp URLDecodeProcessor) WithDescription(description string) IngestProcessor {
	sp.Description = getStringPointer(description)
	return sp
}
