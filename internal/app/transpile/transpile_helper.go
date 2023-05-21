package transpile

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	ast "github.com/breml/logstash-config/ast"
)

type Constraints struct {
	Otherwise  bool
	Conditions []ast.Condition
}

func NewConstraint(_otherwise bool, _conditions ...ast.Condition) Constraints {
	return Constraints{
		Otherwise:  _otherwise,
		Conditions: _conditions,
	}
}

func NewConstraintLiteral() Constraints {
	return Constraints{
		Otherwise:  false,
		Conditions: []ast.Condition{},
	}
}

func AddCondToConstraint(c Constraints, otherwise bool, cond ast.Condition) Constraints {
	newC := Constraints{
		Otherwise:  otherwise,
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
	SetIf(s *string, append bool) IngestProcessor
	SetOnFailure(s []IngestProcessor) IngestProcessor
	// SetTag(string)
}

type SetProcessor struct {
	Value            string            `json:"value,omitempty"`
	Field            string            `json:"field"`
	CopyFrom         string            `json:"copy_from,omitempty"`
	Override         bool              `json:"override,omitempty"`
	IgnoreEmptyValue bool              `json:"ignore_empty_value,omitempty"`
	MediaType        string            `json:"media_type,omitempty"`
	Description      *string           `json:"description,omitempty"`
	If               *string           `json:"if,omitempty"`
	IgnoreFailure    bool              `json:"ignore_failure,omitempty"`
	Tag              string            `json:"tag"`
	OnFailure        []IngestProcessor `json:"on_failure,omitempty"`
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

func (sp SetProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp SetProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

type RemoveProcessor struct {
	Field         *string           `json:"field,omitempty"`
	IgnoreMissing bool              `json:"ignore_missing,omitempty"`
	Keep          []string          `json:"keep,omitempty"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
}

func (ip RemoveProcessor) String() string {
	return StringHelper(ip)
}

func (sp RemoveProcessor) IngestProcessorType() string {
	return "remove"
}

func (sp RemoveProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp RemoveProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
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
	Field         string            `json:"field"`
	TargetField   string            `json:"target_field"`
	IgnoreMissing bool              `json:"ignore_missing"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
}

func (sp RenameProcessor) String() string {
	return StringHelper(sp)
}

func (sp RenameProcessor) IngestProcessorType() string {
	return "rename"
}

func (sp RenameProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp RenameProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
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
	Type          string            `json:"-"` // The field is only used internally to distinguish lowercase/uppercase
	Field         string            `json:"field"`
	TargetField   string            `json:"target_field"`
	IgnoreMissing bool              `json:"ignore_missing,omitempty"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
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

func (sp CaseProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp CaseProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
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
	Description        *string           `json:"description,omitempty"`
	If                 *string           `json:"if,omitempty"`
	IgnoreFailure      bool              `json:"ignore_failure,omitempty"`
	Tag                string            `json:"tag"`
	OnFailure          []IngestProcessor `json:"on_failure,omitempty"`
}

func (gp GrokProcessor) String() string {
	return StringHelper(gp)
}

func (gp GrokProcessor) IngestProcessorType() string {
	return "grok"
}

func (sp GrokProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp GrokProcessor) SetIf(s *string, append bool) IngestProcessor {
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
	Field           string            `json:"field,omitempty"`
	Value           []string          `json:"value,omitempty"`
	AllowDuplicates bool              `json:"allow_duplicates,omitempty"`
	MediaType       *string           `json:"media_type,omitempty"`
	Description     *string           `json:"description,omitempty"`
	If              *string           `json:"if,omitempty"`
	IgnoreFailure   bool              `json:"ignore_failure,omitempty"`
	Tag             string            `json:"tag"`
	OnFailure       []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap AppendProcessor) String() string {
	return StringHelper(ap)
}

func (ap AppendProcessor) IngestProcessorType() string {
	return "append"
}

func (sp AppendProcessor) SetIf(s *string, append bool) IngestProcessor {
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

func (sp AppendProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

type GsubProcessor struct {
	Field         string            `json:"field,omitempty"`
	Pattern       string            `json:"pattern,omitempty"`
	Replacement   string            `json:"replacement"`
	TargetField   *string           `json:"target_field,omitempty"`
	IgnoreMissing bool              `json:"ignore_missing,omitempty"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap GsubProcessor) String() string {
	return StringHelper(ap)
}

func (ap GsubProcessor) IngestProcessorType() string {
	return "gsub"
}

func (sp GsubProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp GsubProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
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
	Field         string            `json:"field,omitempty"`
	Separator     string            `json:"separator,omitempty"`
	TargetField   *string           `json:"target_field,omitempty"`
	IgnoreMissing bool              `json:"ignore_missing,omitempty"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap JoinProcessor) String() string {
	return StringHelper(ap)
}

func (ap JoinProcessor) IngestProcessorType() string {
	return "join"
}

func (sp JoinProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

func (sp JoinProcessor) SetIf(s *string, append bool) IngestProcessor {
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

type KVProcessor struct {
	Field         string            `json:"field,omitempty"`
	FieldSplit    string            `json:"field_split,omitempty"`
	ValueSplit    string            `json:"value_split,omitempty"`
	TargetField   *string           `json:"target_field,omitempty"`
	IncludeKeys   []string          `json:"include_keys,omitempty"`
	ExcludeKeys   []string          `json:"exclude_keys,omitempty"`
	IgnoreMissing bool              `json:"ignore_missing,omitempty"`
	Prefix        *string           `json:"prefix,omitempty"`
	TrimKey       *string           `json:"trim_key,omitempty"`
	TrimValue     *string           `json:"trim_value,omitempty"`
	StripBrackets bool              `json:"strip_bracket,omitempty"`
	Pattern       string            `json:"patterns,omitempty"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap KVProcessor) String() string {
	return StringHelper(ap)
}

func (ap KVProcessor) IngestProcessorType() string {
	return "kv"
}

func (sp KVProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp KVProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
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

type DissectProcessor struct {
	Field           string            `json:"field,omitempty"`
	Pattern         string            `json:"pattern,omitempty"`
	AppendSeparator *string           `json:"append_separator,omitempty"`
	IgnoreMissing   bool              `json:"ignore_missing,omitempty"`
	Description     *string           `json:"description,omitempty"`
	If              *string           `json:"if,omitempty"`
	IgnoreFailure   bool              `json:"ignore_failure,omitempty"`
	Tag             string            `json:"tag"`
	OnFailure       []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap DissectProcessor) String() string {
	return StringHelper(ap)
}

func (ap DissectProcessor) IngestProcessorType() string {
	return "dissect"
}

func (sp DissectProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp DissectProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
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

type DateProcessor struct {
	Field         string            `json:"field,omitempty"`
	TargetField   *string           `json:"target_field,omitempty"` // Default value @timestamp
	Formats       []string          `json:"formats,omitempty"`
	Pattern       string            `json:"patterns,omitempty"`
	Timezone      *string           `json:"timezone,omitempty"`
	Locale        *string           `json:"locale,omitempty"`
	OutputFormat  *string           `json:"output_format,omitempty"` // Default yyyy-MM-dd'T'HH:mm:ss.SSSXXX
	IgnoreMissing bool              `json:"ignore_missing,omitempty"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap DateProcessor) String() string {
	return StringHelper(ap)
}

func (ap DateProcessor) IngestProcessorType() string {
	return "dissect"
}

func (sp DateProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp DateProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
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
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
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

func (sp DropProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp DropProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

type SplitProcessor struct {
	Field            string            `json:"field"`
	Separator        string            `json:"separator"`
	TargetField      *string           `json:"target_field,omitempty"`
	IgnoreMissing    *bool             `json:"ignore_missing,omitempty"`
	PreserveTrailing *bool             `json:"preserve_trailing,omitempty"`
	Description      *string           `json:"description,omitempty"`
	If               *string           `json:"if,omitempty"`
	IgnoreFailure    bool              `json:"ignore_failure,omitempty"`
	Tag              string            `json:"tag"`
	OnFailure        []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap SplitProcessor) String() string {
	return StringHelper(ap)
}

func (ap SplitProcessor) IngestProcessorType() string {
	return "split"
}

func (sp SplitProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp SplitProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
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

type TrimProcessor struct {
	Field            string            `json:"field"`
	TargetField      *string           `json:"target_field,omitempty"`
	IgnoreMissing    *bool             `json:"ignore_missing,omitempty"`
	PreserveTrailing *bool             `json:"preserve_trailing,omitempty"`
	Description      *string           `json:"description,omitempty"`
	If               *string           `json:"if,omitempty"`
	IgnoreFailure    bool              `json:"ignore_failure,omitempty"`
	Tag              string            `json:"tag"`
	OnFailure        []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap TrimProcessor) String() string {
	return StringHelper(ap)
}

func (ap TrimProcessor) IngestProcessorType() string {
	return "trim"
}

func (sp TrimProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp TrimProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
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
	Pipeline              *IngestPipeline   `json:"-"`
	Name                  string            `json:"name"`
	IgnoreMissingPipeline *bool             `json:"ignore_missing_pipeline,omitempty"`
	Description           *string           `json:"description,omitempty"`
	If                    *string           `json:"if,omitempty"`
	IgnoreFailure         bool              `json:"ignore_failure,omitempty"`
	Tag                   *string           `json:"tag,omitempty"`
	OnFailure             []IngestProcessor `json:"on_failure,omitempty"`
}

func (ap PipelineProcessor) String() string {
	return StringHelper(ap)
}

func (ap PipelineProcessor) IngestProcessorType() string {
	return "pipeline"
}
func (sp PipelineProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp PipelineProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
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
	Description   *string                 `json:"description,omitempty"`
	If            *string                 `json:"if,omitempty"`
	IgnoreFailure bool                    `json:"ignore_failure,omitempty"`
	Tag           string                  `json:"tag"`
	OnFailure     []IngestProcessor       `json:"on_failure,omitempty"`
}

func (ap ScriptProcessor) String() string {
	return StringHelper(ap)
}

func (ap ScriptProcessor) IngestProcessorType() string {
	return "script"
}

func (sp ScriptProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp ScriptProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
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
	Field         string            `json:"field"`
	TargetField   *string           `json:"target_field,omitempty"`
	Type          string            `json:"type"`
	IgnoreMissing *bool             `json:"ignore_missing,omitempty"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
}

func (sp ConvertProcessor) String() string {
	return StringHelper(sp)
}

func (sp ConvertProcessor) IngestProcessorType() string {
	return "convert"
}

func (sp ConvertProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp ConvertProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
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
	Field         string            `json:"field"`
	TargetField   *string           `json:"target_field,omitempty"`
	DatabaseFile  *string           `json:"database_file,omitempty"`
	Properties    *[]string         `json:"properties,omitempty"`
	IgnoreMissing *bool             `json:"ignore_missing,omitempty"`
	FirstOnly     *bool             `json:"first_only,omitempty"`
	Description   *string           `json:"description,omitempty"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	Tag           string            `json:"tag"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
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

func (sp GeoIPProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp GeoIPProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}

type UserAgentProcessor struct {
	Field             string            `json:"field"`
	TargetField       *string           `json:"target_field,omitempty"`
	RegexFile         *string           `json:"regex_file,omitempty"`
	Properties        *[]string         `json:"properties,omitempty"`
	ExtractDeviceType string            `json:"extract_deviceType,omitempty"`
	IgnoreMissing     *bool             `json:"ignore_missing,omitempty"`
	Description       *string           `json:"description,omitempty"`
	If                *string           `json:"if,omitempty"`
	IgnoreFailure     bool              `json:"ignore_failure,omitempty"`
	Tag               string            `json:"tag"`
	OnFailure         []IngestProcessor `json:"on_failure,omitempty"`
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

func (sp UserAgentProcessor) SetIf(s *string, append bool) IngestProcessor {
	if append {
		sp.If = AppendIf(sp.If, s)
	} else {
		sp.If = s
	}
	return sp
}

func (sp UserAgentProcessor) SetOnFailure(s []IngestProcessor) IngestProcessor {
	sp.OnFailure = s
	return sp
}
