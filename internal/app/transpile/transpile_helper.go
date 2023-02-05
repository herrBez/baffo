package transpile

import (
	"bytes"
	"encoding/json"
	"log"

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

func processorsArrayToArrayMap(ips []IngestProcessor) []map[string]IngestProcessor {
	output := []map[string]IngestProcessor{}

	for _, ip := range ips {
		output = append(output, ToOutputMap(ip))
	}

	return output
}

func MyJsonEncoder(m map[string]interface{}) string {
	buf := new(bytes.Buffer)

	e := json.NewEncoder(buf)
	e.SetEscapeHTML(false)

	err := e.Encode(m)

	if err != nil {
		// Panic
		log.Panicf("Something wrong in marshalling")
	}
	return string(buf.Bytes())
}

func (ingestPipeline IngestPipeline) String() string {

	m := map[string]interface{}{
		"description": ingestPipeline.Description,
		"processors":  processorsArrayToArrayMap(ingestPipeline.Processors),
	}
	if ingestPipeline.OnFailureProcessors != nil {
		m["on_failure"] = processorsArrayToArrayMap(ingestPipeline.OnFailureProcessors)
	}
	return MyJsonEncoder(m)
}

type IngestProcessor interface {
	String() string
	IngestProcessorType() string
	ToOutputMap() map[string]interface{} // Function that get rid of unneded keys
	// SetTag(string)
}

type SetProcessor struct {
	Value            string            `json:"value,omitempty"`
	Field            string            `json:"field"`
	CopyFrom         string            `json:"copy_from,omitempty"`
	Override         bool              `json:"override,omitempty"`
	IgnoreEmptyValue bool              `json:"ignore_empty_value,omitempty"`
	MediaType        string            `json:"media_type,omitempty"`
	Description      string            `json:"description"`
	If               *string           `json:"if,omitempty"`
	IgnoreFailure    bool              `json:"ignore_failure,omitempty"`
	OnFailure        []IngestProcessor `json:"on_failure,omitempty"`
	Tag              string            `json:"tag"`
}

func ToOutputMap(ip IngestProcessor) map[string]IngestProcessor {
	return map[string]IngestProcessor{
		ip.IngestProcessorType(): ip,
	}
}

func StringHelper(ip IngestProcessor) string {

	return MyJsonEncoder(map[string]interface{}{
		ip.IngestProcessorType(): ip,
	})
}

func (sp SetProcessor) String() string {
	return StringHelper(sp)
}

func (sp SetProcessor) ToOutputMap() map[string]interface{} {
	m := map[string]interface{}{}

	return m
}

func (sp SetProcessor) IngestProcessorType() string {
	return "set"
}

type RenameProcessor struct {
	Field         string            `json:"field"`
	TargetField   string            `json:"target_field"`
	IgnoreMissing bool              `json:"ignore_missing"`
	Description   string            `json:"description"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
	Tag           string            `json:"tag"`
}

func (sp RenameProcessor) String() string {
	return StringHelper(sp)
}

func (sp RenameProcessor) IngestProcessorType() string {
	return "rename"
}

func (sp RenameProcessor) ToOutputMap() map[string]interface{} {
	return map[string]interface{}{}
}

// Type for lowercase/uppercase
type CaseProcessor struct {
	Type          string            `json:"-"` // The field is only used internally to distinguish lowercase/uppercase
	Field         string            `json:"field"`
	TargetField   string            `json:"target_field"`
	IgnoreMissing bool              `json:"ignore_missing,omitempty"`
	Description   string            `json:"description"`
	If            *string           `json:"if,omitempty"`
	IgnoreFailure bool              `json:"ignore_failure,omitempty"`
	OnFailure     []IngestProcessor `json:"on_failure,omitempty"`
	Tag           string            `json:"tag"`
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
