# Transpiler — Supported Components

This document lists the components the transpiler currently recognizes and the Go handler functions that implement them.

| Component | Plugin | Handler | Notes |
|---|---:|---|---|
| input | — | — | No input plugins registered (empty map) |
| filter | [mutate](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-mutate) | `DealWithMutate` | merge not supported|
| filter | [drop](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-drop) | `DealWithDrop` | ✅ |
| filter | [date](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-date) | `DealWithDate` | ✅ |
| filter | [dissect](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-dissect) | `DealWithDissect` | ✅ |
| filter | [grok](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) | `DealWithGrok` | Limited options available (notably no `patterns_dir`) |
| filter | [kv](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-kv) | `DealWithKV` | Limited configuration options supported |
| filter | [cidr](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-cidr) | `DealWithCidr` | 1. Refresh Interval is not supported 2. Converted as script, CIDR netmasks are not computed once |
| filter | [geoip](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-geoip) | `DealWithGeoIP` | Limited options available |
| filter | [translate](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-translate) | `DealWithTranslate` | ✅ (No external file dictionary available) |
| filter | [useragent](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-useragent) | `DealWithUserAgent` | ✅ (Caveats do apply with [ecs_compatibility: false](https://github.com/herrBez/baffo/issues/9)) |
| filter | [urldecode](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-urldecode) | `DealWithURLDecode` | ✅ (Charset not supported) |
| filter | [prune](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-prune) | `DealWithPrune` | Limited support |
| filter | [syslog_pri](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-syslog_pri) | `DealWithSyslogPri` | ✅ (Converted as script) |
| filter | [csv](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-csv) | `DealWithCSV` | ✅ (Notably `autodetect_column_names` and `autogenearte_column_names` not supported) |
| filter | [json](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-json) | `DealWithJSON` | Limited options availale source and target. TODO: Add ecs_compatibility support|
| filter | [truncate](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-truncate) | `DealWithTruncate` | Commented out in source (not active) |
| output | [elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch) | `DealWithOutputElasticsearch` | We simply invoke the ingest pipeline specified in the Elasticsearch output if any |
| output | [pipeline](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-pipeline) | `DealWithOutputPipeline` | Experimental: We add a pipeline processor to invoke the (converted) invoked pipeline |

Notes
- The transpiler map shape is: map[string]map[string]TranspileProcessor — top-level keys are component types (`input`, `filter`, `output`).
- To add a plugin, register its handler in the appropriate sub-map with the plugin name as key.
- The `input` map is currently empty; inputs are not handled by this transpiler yet.

Example: adding a new filter handler (Go)
```go
transpiler["filter"]["myplugin"] = DealWithMyPlugin
```