package transpile

import (
	"fmt"

	ast "github.com/breml/logstash-config/ast"
)

type ApplyPluginsFuncCondition func(cursor *Cursor, c Constraints, ip *IngestPipeline)

func mergeWithIPFidelity(ip *IngestPipeline, tmp_ip IngestPipeline, cond *string, threshold int) {
	if len(tmp_ip.Processors) < threshold {
		for _, tp := range tmp_ip.Processors {
			ip.Processors = append(ip.Processors, tp.WithIf(cond, false))
		}
	} else {
		ip.Processors = append(ip.Processors,
			PipelineProcessor{
				Pipeline: &tmp_ip,
				Name:     tmp_ip.Name,
			}.WithIf(cond, false),
		)
	}
}

// ApplyPlugins traverses an AST recursively, starting with root, and calling
// applyPluginsFunc for each plugin. Apply returns the AST, possibly modified.
func (t Transpile) MyIteration(root []ast.BranchOrPlugin, constraint Constraints, applyPluginsFunc ApplyPluginsFuncCondition, ip *IngestPipeline) IngestPipeline {
	c := Cursor{
		parent: root,
		iter: iterator{
			index: 0,
			step:  1,
		},
	}

	for {
		if c.iter.index >= len(c.parent) {
			break
		}

		c.iter.step = 1

		switch block := c.parent[c.iter.index].(type) {

		case ast.Branch:
			branchName := fmt.Sprintf("%s-branch-%d", ip.Name, c.iter.index)

			currentConstraints := constraint
			// var elseConstraint Constraints

			NotOperator := ast.BooleanOperator{
				Op:    ast.NoOperator,
				Start: block.Pos(),
			}

			// Compute the conditions before executing the branches to keep the same
			// semantic of if, else-if, ..., else
			baseConstraint := transpileConstraint(constraint)
			script := "if ctx.containsKey('_TRANSPILER') { ctx['_TRANSPILER'] = [:]; }\n"
			if baseConstraint != nil {
				script = script + fmt.Sprintf(`def ctx._TRANSPILER['%s-base'] = %s;\n`, branchName, *baseConstraint)
			} else {
				script = script + fmt.Sprintf(`def ctx._TRANSPILER['%s-base'] = true;\n`, branchName)
			}

			oldConstraints := constraint
			currentConstraints = AddCondToConstraint(oldConstraints, block.IfBlock.Condition)
			baseConstraint = transpileConstraint(currentConstraints)

			if baseConstraint != nil {
				script = script + fmt.Sprintf(`def ctx._TRANSPILER['%s-if"] = %s;\n`, branchName, *baseConstraint)
			}

			currentConstraints = AddCondToConstraint(constraint, ast.NewCondition(ast.NewNegativeConditionExpression(NotOperator, block.IfBlock.Condition)))

			for i := range block.ElseIfBlock {

				oldConstraints := currentConstraints
				currentConstraints = AddCondToConstraint(oldConstraints, block.ElseIfBlock[i].Condition)

				script = script + fmt.Sprintf(`def ctx._TRANSPILER['%s-elif-%d'] = %s;\n`, branchName, i, *transpileConstraint(currentConstraints))

				currentConstraints = AddCondToConstraint(oldConstraints, ast.NewCondition(ast.NewNegativeConditionExpression(NotOperator, block.ElseIfBlock[i].Condition)))

			}

			script = script + fmt.Sprintf(`def ctx._TRANSPILER['%s-else'] = %s;`, branchName, *transpileConstraint(currentConstraints))

			if t.fidelity {
				ip.Processors = append(ip.Processors, ScriptProcessor{
					Source: &script,
				}.WithDescription("Compute the branch conditions before executing the branches to avoid possible semantic errors"))
			}
			// IF
			// compute the current Constraint "inherited + if condition"
			// create a new temporary pipeline and iterate recursively
			// Merge the current Pipeline and the temporary Pipeline

			oldConstraints = constraint
			currentConstraints = AddCondToConstraint(oldConstraints, block.IfBlock.Condition)

			tmp_ip := NewIngestPipeline(fmt.Sprintf("%s-if", branchName))

			t.MyIteration(block.IfBlock.Block, NewConstraintLiteral(), applyPluginsFunc, &tmp_ip)

			var cond *string

			if !t.fidelity {
				cond = transpileConstraint(currentConstraints)
			} else {
				cond = pointer(fmt.Sprintf("ctx._TRANSPILER['%s-if']", branchName))
			}

			// mergeWithIP(ip, tmp_ip, currentConstraints, t.threshold)
			mergeWithIPFidelity(ip, tmp_ip, cond, t.threshold)

			// Else-If
			// else-if-1 constraint = "inherited + negate if condition"
			// else-if-2 constraint = "inherited + negate if condition + negate elseif 1 constraint"
			// ...

			currentConstraints = AddCondToConstraint(constraint, ast.NewCondition(ast.NewNegativeConditionExpression(NotOperator, block.IfBlock.Condition)))

			for i := range block.ElseIfBlock {
				tmp_ip = NewIngestPipeline(fmt.Sprintf("%s-elif-%d", branchName, i))

				t.MyIteration(block.ElseIfBlock[i].Block, NewConstraintLiteral(), applyPluginsFunc, &tmp_ip)

				oldConstraints := currentConstraints
				currentConstraints = AddCondToConstraint(oldConstraints, block.ElseIfBlock[i].Condition)

				// mergeWithIP(ip, tmp_ip, currentConstraints, t.threshold)

				if !t.fidelity {
					cond = transpileConstraint(currentConstraints)
				} else {
					cond = pointer(fmt.Sprintf("ctx._TRANSPILER['%s-else']", branchName))
				}

				mergeWithIPFidelity(ip, tmp_ip, cond, t.threshold)

				currentConstraints = AddCondToConstraint(oldConstraints, ast.NewCondition(ast.NewNegativeConditionExpression(NotOperator, block.ElseIfBlock[i].Condition)))

			}

			// Else
			// else condition = "inherited + negate if condition + for 1..N negate else if $i condition"
			tmp_ip = NewIngestPipeline(fmt.Sprintf("%s-else", branchName))
			t.MyIteration(block.ElseBlock.Block, NewConstraintLiteral(), applyPluginsFunc, &tmp_ip)

			if !t.fidelity {
				cond = transpileConstraint(currentConstraints)
			} else {
				cond = pointer(fmt.Sprintf("ctx._TRANSPILER['%s-else']", branchName))
			}
			// mergeWithIP(ip, tmp_ip, currentConstraints, t.threshold)
			mergeWithIPFidelity(ip, tmp_ip, cond, t.threshold)

			c.parent[c.iter.index] = block

		case ast.Plugin:
			applyPluginsFunc(&c, constraint, ip)

		case nil:
			applyPluginsFunc(&c, constraint, ip)

		default:
			panic(fmt.Sprintf("type %T for block in ApplyPlugins not supported", c.parent[c.iter.index]))
		}

		c.iter.index += c.iter.step
	}

	return NewIngestPipeline("placeholder")
}

// An iterator controls iteration over a slice of nodes.
type iterator struct {
	index, step int
}

// A Cursor describes a plugin encountered during ApplyPlugins.
// Information about the node and its parent is available from the Plugin,
// Parent and Index methods.
//
// The methods Replace and Delete can be used to change the AST without
// disrupting ApplyPlugins.
type Cursor struct {
	parent []ast.BranchOrPlugin
	iter   iterator // valid if non-nil
}

// Plugin returns the current Plugin.
func (c *Cursor) Plugin() *ast.Plugin {
	p, ok := c.parent[c.iter.index].(ast.Plugin)
	if !ok {
		var p *ast.Plugin
		return p
	}
	return &p
}

// Parent returns the slice of BranchOrPlugin of the current Plugin.
func (c *Cursor) Parent() []ast.BranchOrPlugin { return c.parent }

// Index reports the index of the current Plugin in the slice of BranchOrPlugin
// that contains it.
func (c *Cursor) Index() int {
	return c.iter.index
}

// Delete deletes the current Plugin from its containing slice.
// If the current Plugin is not part of a slice, Delete panics.
func (c *Cursor) Delete() {
	i := c.Index()
	if i < 0 {
		panic("Delete plugin not contained in slice")
	}
	c.parent = append(c.parent[:i], c.parent[i+1:]...)
	c.iter.step--
}

// Replace replaces the current Plugin with p.
// The replacement is not walked by Apply.
// If the current Plugin is not part of a slice, Replace panics.
func (c *Cursor) Replace(p ast.BranchOrPlugin) {
	i := c.Index()
	if i < 0 {
		panic("Replaced plugin not contained in slice")
	}
	c.parent[i] = p
}

// InsertBefore inserts p before the current Plugin in its containing slice.
// If the current Node is not part of a slice, InsertBefore panics.
// Apply will not walk p.
func (c *Cursor) InsertBefore(p ast.BranchOrPlugin) {
	i := c.Index()
	if i < 0 {
		panic("InsertBefore plugin not contained in slice")
	}
	c.parent = append(c.parent[:i], append([]ast.BranchOrPlugin{p}, c.parent[i:]...)...)
	c.iter.step++
}

// InsertAfter inserts p after the current Plugin in its containing slice.
// If the current Node is not part of a slice, InsertAfter panics.
// Apply will not walk p.
func (c *Cursor) InsertAfter(p ast.BranchOrPlugin) {
	i := c.Index()
	if i < 0 {
		panic("InsertAfter plugin not contained in slice")
	}
	c.parent = append(c.parent[:i+1], append([]ast.BranchOrPlugin{p}, c.parent[i+1:]...)...)
	c.iter.step++
}
