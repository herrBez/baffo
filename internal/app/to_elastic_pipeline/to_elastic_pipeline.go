


type ElasticPipeline struct {
	Description string
	Processors []Processor
	OnFailue []Processor
}



type Processor interface {
	Name() string
	Tag() string
}

type SetProcessor struct {
	Field string // Req
	Calue string // Req
	CopyFrom string 
	Tag string
	If PCondition
}


struct PCondition {
	
}