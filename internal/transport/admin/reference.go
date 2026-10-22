package admin

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/fatihacan1/warden/api"
)

// refGroup is one tag of the API reference shown on the docs page.
type refGroup struct {
	Tag         string
	Description string
	Ops         []refOp
}

type refOp struct {
	Method  string
	Path    string
	Summary string
	Detail  string
	Auth    string
	ID      string
}

// buildReference turns the embedded OpenAPI document into a compact list of
// endpoints. The document is the single source of truth: it ships in the
// binary and is also downloadable from the docs page.
func buildReference() ([]refGroup, error) {
	var doc struct {
		Tags []struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
		} `yaml:"tags"`
		Security []map[string]any                `yaml:"security"`
		Paths    map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPI, &doc); err != nil {
		return nil, err
	}
	order := map[string]int{}
	groups := []refGroup{}
	for i, t := range doc.Tags {
		order[t.Name] = i
		groups = append(groups, refGroup{Tag: t.Name, Description: t.Description})
	}
	methods := []string{"get", "post", "put", "patch", "delete"}
	for path, item := range doc.Paths {
		for _, m := range methods {
			node, ok := item[m]
			if !ok {
				continue
			}
			var op struct {
				Tags        []string          `yaml:"tags"`
				Summary     string            `yaml:"summary"`
				Description string            `yaml:"description"`
				OperationID string            `yaml:"operationId"`
				Security    *[]map[string]any `yaml:"security"`
			}
			if err := node.Decode(&op); err != nil {
				return nil, err
			}
			tag := "Other"
			if len(op.Tags) > 0 {
				tag = op.Tags[0]
			}
			idx, ok := order[tag]
			if !ok {
				idx = len(groups)
				order[tag] = idx
				groups = append(groups, refGroup{Tag: tag})
			}
			sec := doc.Security
			if op.Security != nil {
				sec = *op.Security
			}
			groups[idx].Ops = append(groups[idx].Ops, refOp{
				Method: strings.ToUpper(m), Path: path, Summary: op.Summary, Detail: firstLine(op.Description),
				Auth: authLabel(sec), ID: op.OperationID,
			})
		}
	}
	for i := range groups {
		sort.SliceStable(groups[i].Ops, func(a, b int) bool {
			if groups[i].Ops[a].Path != groups[i].Ops[b].Path {
				return groups[i].Ops[a].Path < groups[i].Ops[b].Path
			}
			return methodRank(groups[i].Ops[a].Method) < methodRank(groups[i].Ops[b].Method)
		})
	}
	out := groups[:0]
	for _, g := range groups {
		if len(g.Ops) > 0 {
			out = append(out, g)
		}
	}
	return out, nil
}

func methodRank(m string) int {
	return strings.Index("GET POST PUT PATCH DELETE", m)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func authLabel(sec []map[string]any) string {
	if len(sec) == 0 {
		return "Public"
	}
	var names []string
	for _, req := range sec {
		for k := range req {
			switch k {
			case "bearer":
				names = append(names, "Access token")
			case "secretKey":
				names = append(names, "Secret key")
			default:
				names = append(names, k)
			}
		}
	}
	if len(names) == 0 {
		return "Public"
	}
	return strings.Join(names, " or ")
}
