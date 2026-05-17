package output

import (
	"fmt"
	"html"
	"io"
	"math"
	"strings"
)

func WriteHTML(result *AnalysisResult, w io.Writer) error {
	_, err := io.WriteString(w, htmlDoc(result))
	return err
}

func htmlDoc(r *AnalysisResult) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GoRipper: `)
	b.WriteString(html.EscapeString(r.BinaryInfo.Path))
	b.WriteString(`</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"SF Mono","Fira Code",monospace;font-size:13px;background:#0d1117;color:#c9d1d9;line-height:1.5}
a{color:#58a6ff;text-decoration:none}
header{background:#161b22;border-bottom:1px solid #30363d;padding:16px 24px;display:flex;align-items:center;gap:16px}
header h1{font-size:16px;font-weight:600;color:#f0f6fc}
header .badge{background:#21262d;border:1px solid #30363d;border-radius:4px;padding:2px 8px;font-size:11px;color:#8b949e}
nav{background:#161b22;border-bottom:1px solid #30363d;padding:0 24px;display:flex;gap:0;overflow-x:auto}
nav a{display:block;padding:8px 14px;color:#8b949e;border-bottom:2px solid transparent;white-space:nowrap}
nav a:hover{color:#c9d1d9;border-bottom-color:#30363d}
main{padding:24px;max-width:1400px;margin:0 auto}
section{margin-bottom:32px}
section h2{font-size:14px;font-weight:600;color:#f0f6fc;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #21262d}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;min-width:140px}
.card .label{font-size:11px;color:#8b949e;margin-bottom:4px}
.card .value{font-size:18px;font-weight:600;color:#f0f6fc}
.card .sub{font-size:11px;color:#8b949e;margin-top:2px}
.warn{background:#1c1208;border:1px solid #3d2b00;border-radius:6px;padding:8px 12px;color:#d29922;margin-bottom:8px}
.info-grid{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px}
.info-grid .k{color:#8b949e}
.info-grid .v{color:#c9d1d9}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:6px;overflow:hidden}
th{background:#1c2128;color:#8b949e;font-weight:500;padding:8px 10px;text-align:left;border-bottom:1px solid #30363d;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
td{padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2128}
.tag{display:inline-block;background:#21262d;border:1px solid #30363d;border-radius:3px;padding:0 5px;font-size:11px;margin:1px}
.tag.net{background:#0d2045;border-color:#1f6feb;color:#79c0ff}
.tag.crypto{background:#1a1404;border-color:#6e7a00;color:#e3c000}
.tag.file{background:#0a1f0a;border-color:#2ea043;color:#56d364}
.tag.mem{background:#1a0e0e;border-color:#8b2929;color:#f87171}
.verdict-normal{color:#56d364}
.verdict-compressed{color:#d29922}
.verdict-encrypted{color:#f87171}
.verdict-packed{color:#8b949e}
.entropy-bar{height:10px;border-radius:2px;display:inline-block;vertical-align:middle}
.filter-row{display:flex;gap:8px;margin-bottom:10px}
.filter-row input{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:5px 10px;color:#c9d1d9;font-family:inherit;font-size:12px;flex:1}
.filter-row input:focus{outline:none;border-color:#58a6ff}
.addr{color:#8b949e;font-size:11px}
.pkg{color:#8b949e}
.kind-user{color:#79c0ff}
.kind-stdlib{color:#56d364}
.kind-runtime{color:#8b949e}
.kind-cgo{color:#d29922}
.hidden{display:none}
.packer-badge{background:#2d1a00;border:1px solid #8b4513;border-radius:4px;padding:2px 8px;color:#d29922;font-size:11px}
</style>
</head>
<body>
`)

	b.WriteString(`<header>`)
	b.WriteString(`<h1>GoRipper Analysis</h1>`)
	b.WriteString(`<span class="badge">` + html.EscapeString(r.BinaryInfo.Format) + `</span>`)
	b.WriteString(`<span class="badge">` + html.EscapeString(r.BinaryInfo.Arch) + `</span>`)
	if r.BinaryInfo.GoVersion != "" {
		b.WriteString(`<span class="badge">` + html.EscapeString(r.BinaryInfo.GoVersion) + `</span>`)
	}
	if r.BinaryInfo.Packer != "" {
		b.WriteString(`<span class="packer-badge">` + html.EscapeString(r.BinaryInfo.Packer) + `</span>`)
	}
	b.WriteString(`</header>`)

	b.WriteString(`<nav>`)
	b.WriteString(`<a href="#summary">Summary</a>`)
	if len(r.BinaryInfo.Sections) > 0 {
		b.WriteString(`<a href="#sections">Entropy</a>`)
	}
	b.WriteString(`<a href="#functions">Functions</a>`)
	b.WriteString(`<a href="#strings">Strings</a>`)
	if len(r.EmbeddedAssets) > 0 {
		b.WriteString(`<a href="#assets">Assets</a>`)
	}
	if len(r.Types) > 0 {
		b.WriteString(`<a href="#types">Types</a>`)
	}
	if len(r.TaintFlows) > 0 {
		b.WriteString(`<a href="#taint">Taint</a>`)
	}
	if len(r.Warnings) > 0 {
		b.WriteString(`<a href="#warnings">Warnings</a>`)
	}
	b.WriteString(`</nav>`)

	b.WriteString(`<main>`)

	if len(r.Warnings) > 0 {
		b.WriteString(`<section id="warnings">`)
		for _, w := range r.Warnings {
			b.WriteString(`<div class="warn">` + html.EscapeString(w) + `</div>`)
		}
		b.WriteString(`</section>`)
	}

	b.WriteString(`<section id="summary">`)
	b.WriteString(`<h2>Summary</h2>`)
	b.WriteString(`<div class="info-grid">`)
	b.WriteString(`<span class="k">Path</span><span class="v">` + html.EscapeString(r.BinaryInfo.Path) + `</span>`)
	b.WriteString(`<span class="k">Format</span><span class="v">` + html.EscapeString(r.BinaryInfo.Format) + `</span>`)
	b.WriteString(`<span class="k">Arch</span><span class="v">` + html.EscapeString(r.BinaryInfo.Arch) + `</span>`)
	if r.BinaryInfo.GoVersion != "" {
		b.WriteString(`<span class="k">Go Version</span><span class="v">` + html.EscapeString(r.BinaryInfo.GoVersion) + `</span>`)
	}
	if r.BinaryInfo.PclntabVersion != "" {
		b.WriteString(`<span class="k">Pclntab</span><span class="v">` + html.EscapeString(r.BinaryInfo.PclntabVersion) + ` &nbsp; <span style="color:#8b949e">` + html.EscapeString(r.BinaryInfo.PclntabMagic) + `</span></span>`)
	}
	b.WriteString(fmt.Sprintf(`<span class="k">Size</span><span class="v">%d bytes</span>`, r.BinaryInfo.SizeBytes))
	if r.BinaryInfo.Packer != "" {
		b.WriteString(`<span class="k">Packer</span><span class="v packer-badge">` + html.EscapeString(r.BinaryInfo.Packer) + `</span>`)
	}
	if r.BinaryInfo.ObfuscationLevel != "" && r.BinaryInfo.ObfuscationLevel != "none" {
		b.WriteString(fmt.Sprintf(`<span class="k">Obfuscation</span><span class="v">%.2f [%s]</span>`,
			r.BinaryInfo.ObfuscationScore, html.EscapeString(r.BinaryInfo.ObfuscationLevel)))
	}
	b.WriteString(`</div>`)

	b.WriteString(`<br><div class="cards">`)
	b.WriteString(summaryCard("Functions", fmt.Sprint(r.Summary.TotalFunctions),
		fmt.Sprintf("%d user · %d stdlib · %d runtime", r.Summary.UserFunctions, r.Summary.StdlibFunctions, r.Summary.RuntimeFunctions)))
	b.WriteString(summaryCard("Strings", fmt.Sprint(r.Summary.TotalStrings),
		fmt.Sprintf("%d URLs · %d IPs · %d secrets", r.Summary.URLStrings, r.Summary.IPStrings, r.Summary.SecretStrings)))
	b.WriteString(summaryCard("Suspicious", fmt.Sprint(r.Summary.SuspiciousFunctions), "functions with behavior tags"))
	b.WriteString(summaryCard("Concurrent", fmt.Sprint(r.Summary.ConcurrentFunctions), "functions using goroutines/channels"))
	if r.Summary.RecoveredTypes > 0 {
		b.WriteString(summaryCard("Types", fmt.Sprint(r.Summary.RecoveredTypes), fmt.Sprintf("%d interface impls", r.Summary.InterfaceImpls)))
	}
	if r.Summary.EmbeddedAssets > 0 {
		b.WriteString(summaryCard("Assets", fmt.Sprint(r.Summary.EmbeddedAssets), "embedded files detected"))
	}
	if r.Summary.DecryptorStubs > 0 {
		b.WriteString(summaryCard("Decryptor Stubs", fmt.Sprint(r.Summary.DecryptorStubs), "suspected string encryption"))
	}
	if r.Summary.ThreatClass != "" {
		b.WriteString(summaryCard("Threat", r.Summary.ThreatClass, r.Summary.ThreatConfidence+" confidence"))
	}
	if r.Summary.TaintFlows > 0 {
		b.WriteString(summaryCard("Taint Flows", fmt.Sprint(r.Summary.TaintFlows), "source → sink paths"))
	}
	b.WriteString(`</div></section>`)

	if len(r.BinaryInfo.Sections) > 0 {
		b.WriteString(`<section id="sections"><h2>Section Entropy</h2>`)
		b.WriteString(entropyChart(r.BinaryInfo.Sections))
		b.WriteString(`<table><thead><tr><th>Section</th><th>Size</th><th>Entropy</th><th>Verdict</th></tr></thead><tbody>`)
		for _, s := range r.BinaryInfo.Sections {
			cls := "verdict-" + s.Verdict
			b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%.4f</td><td class="%s">%s</td></tr>`,
				html.EscapeString(s.Name), s.Size, s.Entropy, cls, html.EscapeString(s.Verdict)))
		}
		b.WriteString(`</tbody></table></section>`)
	}

	b.WriteString(`<section id="functions"><h2>Functions (` + fmt.Sprint(len(r.Functions)) + `)</h2>`)
	b.WriteString(`<div class="filter-row"><input type="text" id="fn-filter" placeholder="Filter by name or package..." oninput="filterTable('fn-table','fn-filter',0)"></div>`)
	b.WriteString(`<table id="fn-table"><thead><tr><th>Address</th><th>Name</th><th>Package</th><th>Size</th><th>Tags</th></tr></thead><tbody>`)
	for _, fn := range r.Functions {
		kindCls := "kind-" + fn.PackageKind
		tags := htmlTags(fn.Tags)
		b.WriteString(fmt.Sprintf(`<tr><td class="addr">%s</td><td>%s</td><td class="pkg %s">%s</td><td>%d</td><td>%s</td></tr>`,
			html.EscapeString(fn.Addr),
			html.EscapeString(fn.Name),
			kindCls, html.EscapeString(fn.Package),
			fn.Size, tags))
	}
	b.WriteString(`</tbody></table></section>`)

	b.WriteString(`<section id="strings"><h2>Strings (` + fmt.Sprint(len(r.Strings)) + `)</h2>`)
	b.WriteString(`<div class="filter-row"><input type="text" id="str-filter" placeholder="Filter strings..." oninput="filterTable('str-table','str-filter',0)"></div>`)
	b.WriteString(`<table id="str-table"><thead><tr><th>Value</th><th>Type</th><th>Referenced By</th></tr></thead><tbody>`)
	for _, s := range r.Strings {
		refs := ""
		if len(s.ReferencedBy) > 0 {
			refs = html.EscapeString(strings.Join(s.ReferencedBy, ", "))
		}
		b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><span class="tag">%s</span></td><td class="pkg">%s</td></tr>`,
			html.EscapeString(s.Value), html.EscapeString(s.Type), refs))
	}
	b.WriteString(`</tbody></table></section>`)

	if len(r.EmbeddedAssets) > 0 {
		b.WriteString(`<section id="assets"><h2>Embedded Assets (` + fmt.Sprint(len(r.EmbeddedAssets)) + `)</h2>`)
		b.WriteString(`<table><thead><tr><th>Path</th></tr></thead><tbody>`)
		for _, a := range r.EmbeddedAssets {
			b.WriteString(`<tr><td>` + html.EscapeString(a.Path) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table></section>`)
	}

	if len(r.Types) > 0 {
		b.WriteString(`<section id="types"><h2>Recovered Types (` + fmt.Sprint(len(r.Types)) + `)</h2>`)
		b.WriteString(`<table><thead><tr><th>Name</th><th>Kind</th><th>Size</th><th>Fields</th></tr></thead><tbody>`)
		for _, t := range r.Types {
			fields := ""
			if len(t.Fields) > 0 {
				fieldNames := make([]string, 0, len(t.Fields))
				for _, f := range t.Fields {
					fieldNames = append(fieldNames, f.Name+" "+f.Type)
				}
				fields = html.EscapeString(strings.Join(fieldNames, ", "))
			}
			b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><span class="tag">%s</span></td><td>%d</td><td class="pkg">%s</td></tr>`,
				html.EscapeString(t.Name), html.EscapeString(t.Kind), t.Size, fields))
		}
		b.WriteString(`</tbody></table></section>`)
	}

	if len(r.TaintFlows) > 0 {
		b.WriteString(`<section id="taint"><h2>Taint Flows (` + fmt.Sprint(len(r.TaintFlows)) + `)</h2>`)
		b.WriteString(`<table><thead><tr><th>Confidence</th><th>Source</th><th>Source Func</th><th>Sink</th><th>Sink Func</th><th>Hops</th></tr></thead><tbody>`)
		for _, tf := range r.TaintFlows {
			b.WriteString(fmt.Sprintf(`<tr><td><span class="tag">%s</span></td><td>%s</td><td class="pkg">%s</td><td>%s</td><td class="pkg">%s</td><td>%d</td></tr>`,
				html.EscapeString(tf.Confidence),
				html.EscapeString(tf.Source),
				html.EscapeString(tf.SourceFunc),
				html.EscapeString(tf.Sink),
				html.EscapeString(tf.SinkFunc),
				len(tf.Path)))
		}
		b.WriteString(`</tbody></table></section>`)
	}

	b.WriteString(`</main>`)

	b.WriteString(`<script>
function filterTable(tableId, inputId, col) {
  var q = document.getElementById(inputId).value.toLowerCase();
  var rows = document.getElementById(tableId).tBodies[0].rows;
  for (var i = 0; i < rows.length; i++) {
    var text = rows[i].textContent.toLowerCase();
    rows[i].classList.toggle('hidden', q !== '' && text.indexOf(q) === -1);
  }
}
</script>`)

	b.WriteString(`</body></html>`)
	return b.String()
}

func summaryCard(label, value, sub string) string {
	return fmt.Sprintf(`<div class="card"><div class="label">%s</div><div class="value">%s</div><div class="sub">%s</div></div>`,
		html.EscapeString(label), html.EscapeString(value), html.EscapeString(sub))
}

func htmlTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	var b strings.Builder
	for _, t := range tags {
		cls := "tag"
		switch t {
		case "NETWORK", "HTTP", "DNS":
			cls += " net"
		case "CRYPTO":
			cls += " crypto"
		case "FILE_WRITE", "FILE_READ":
			cls += " file"
		case "MEMORY":
			cls += " mem"
		}
		b.WriteString(`<span class="` + cls + `">` + html.EscapeString(t) + `</span>`)
	}
	return b.String()
}

func entropyChart(sections []SectionInfo) string {
	if len(sections) == 0 {
		return ""
	}
	const svgWidth = 600
	const barH = 18
	const barGap = 6
	const labelW = 140
	const chartW = svgWidth - labelW - 50
	const maxEntropy = 8.0

	svgH := (barH+barGap)*len(sections) + 10

	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<svg width="%d" height="%d" style="display:block;margin-bottom:12px" xmlns="http://www.w3.org/2000/svg">`, svgWidth, svgH))

	for i, s := range sections {
		y := i*(barH+barGap) + 5
		ratio := s.Entropy / maxEntropy
		if ratio > 1 {
			ratio = 1
		}
		barW := int(math.Round(float64(chartW) * ratio))
		color := "#238636" // normal — green
		switch s.Verdict {
		case "compressed":
			color = "#d29922" // yellow
		case "encrypted":
			color = "#da3633" // red
		case "packed":
			color = "#484f58" // grey
		}

		// Section name label
		b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" fill="#8b949e" font-size="11" font-family="monospace" text-anchor="end">%s</text>`,
			labelW-4, y+barH-4, html.EscapeString(s.Name)))
		// Background track
		b.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" rx="2" fill="#21262d"/>`,
			labelW, y, chartW, barH))
		// Entropy bar
		if barW > 0 {
			b.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" rx="2" fill="%s"/>`,
				labelW, y, barW, barH, color))
		}
		// Entropy value
		b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" fill="#c9d1d9" font-size="11" font-family="monospace">%.2f</text>`,
			labelW+chartW+6, y+barH-4, s.Entropy))
	}
	b.WriteString(`</svg>`)
	return b.String()
}
