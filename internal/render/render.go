package render

import (
	"bytes"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

var nonAlnumRe = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// UpstreamName derives a safe nginx upstream block name from a pipeline_ref.
func UpstreamName(ref string) string {
	safe := nonAlnumRe.ReplaceAllString(ref, "_")
	safe = strings.Trim(safe, "_")
	if safe == "" {
		safe = "app"
	}
	return safe + "_pool"
}

// ManagedByHeader is the exact first line every rendered/managed conf file
// carries. Its presence is what authorizes the listener to overwrite/delete
// a file (§2.2 "sempre com o header # managed-by: na primeira linha").
func ManagedByHeader(p Payload) string {
	return "# managed-by: deployer-lb-server app=" + p.PipelineRef + " revision=" + strconv.FormatInt(p.Revision, 10)
}

var funcMap = template.FuncMap{
	"join":         strings.Join,
	"upstreamName": UpstreamName,
}

// Render executes the nginx vhost template (loaded from templatePath) against
// payload p, using text/template (never html/template — this output is nginx
// config, not HTML).
func Render(templatePath string, p Payload) (string, error) {
	raw, err := os.ReadFile(templatePath)
	if err != nil {
		return "", err
	}
	return RenderString(string(raw), p)
}

// RenderString is like Render but takes the template text directly; used by
// tests that don't want to depend on a file on disk.
func RenderString(tmplText string, p Payload) (string, error) {
	tmpl, err := template.New("nginx-app").Funcs(funcMap).Parse(tmplText)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", err
	}
	return buf.String(), nil
}
