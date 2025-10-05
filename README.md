# Baffo

A **fork of [logstash-config](https://github.com/breml/logstash-config)** with a new `transpile` command that converts **Logstash Pipelines** into **Elasticsearch Ingest Pipeline syntax**.

[![Test Status](https://github.com/herrBez/baffo/workflows/Test/badge.svg)](https://github.com/herrBez/baffo/actions?query=workflow%3ATest)
[![Go Report Card](https://goreportcard.com/badge/github.com/herrBez/baffo)](https://goreportcard.com/report/github.com/herrBez/baffo)
[![GoDoc](https://pkg.go.dev/badge/github.com/herrBez/baffo)](https://pkg.go.dev/github.com/herrBez/baffo)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

---

## Overview

`baffo` provides a Go parser for Logstash configuration files, based on the original [Logstash Treetop grammar](https://github.com/elastic/logstash/blob/master/logstash-core/lib/logstash/config/grammar.treetop).  
It uses [pigeon](https://github.com/mna/pigeon) to generate the parser from a PEG (Parsing Expression Grammar).

This fork adds the **`transpile` command**, allowing you to convert existing Logstash pipelines into Elasticsearch ingest pipelines — no temporary files needed.

> ⚠️ This package is under active development. API stability is **not guaranteed**.

---

## Install

```bash
go install github.com/herrBez/baffo/cmd/baffo@latest
```


## Name overview

The word `baffo` means `moustache` in Italian, chosen to clearly indicate that this project is a fork of the original Mustache. The original name is inspired by the original Logstash Logo ([wooden character with an eye-catching mustache](https://www.elastic.co/de/blog/high-level-logstash-roadmap-is-published)).


### Baffo

`baffo` is a CLI tool to check, lint, format, and transpile Logstash configuration files.

#### Transpile

The `transpile` command transpiles a Logstash Pipelines to one or more Elasticsearch Ingest Pipelines:

```shell
baffo transpile file.conf
```


For the transpilation we have different flags at disposal:

- `add_default_global_on_failure`: whether to add a default global on failure processor
- `deal_with_error_locally`: whether to deal with the errors locally à là Logstash (e.g., by adding the tag on error by default)
- `fidelity`: whether we want to keep the correct the if-else semantic, i.e., calculating the condition only once
- `pipeline_threshold`: determine how many processors will cause the creation of a new pipeline when converting if-else statements

By default, we try to keep the semantics as close as possible with the original Logstash Pipeline. To obtain idiomatic pipelines, consider using the following settings:

```
baffo transpile file.conf \
  --deal_with_error_locally=false \
  --pipeline_threshold=10 \
  --add_default_global_on_failure=true \
  --fidelity=false
```

> ⚠️ Disclaimer: Semantic equivalence between the input Logstash pipelines and the generated Elasticsearch ingest pipelines is not formally guaranteed. The output should not be used in production without careful review and testing.


#### Check 

The `check` command verifies the syntax of Logstash configuration files:

```shell
baffo check file.conf
```

#### Lint

The `lint` command checks for problems in Logstash configuration files.

The following checks are performed:

* Valid Logstash configuration file syntax
* No comments in exceptional places (these are comments, that are valid by the Logstash configuration file syntax, but
  but are located in exceptional or uncommon locations)
* Precence of an `id` attribute for each plugin in the Logstash configuration

If the `--auto-fix-id` flag is passed, each plugin gets automatically an ID. Be aware, that this potentially reformats
the Logstash configuration files.

```shell
baffo lint --auto-fix-id file.conf
```

#### format

With the `format` command, mustache returns the provided configuration files in a standardized format (indentation,
location of comments). By default, the reformatted file is print to standard out. If the flag `--write-to-source`
is provided, the Logstash config files are reformatted in place.

```shell
mustache format --write-to-source file.conf
```

Use the `--help` flag to get more information about the usage of the tool.

## Rebuild parser

1. Get and install [pigeon](https://github.com/mna/pigeon).
2. Run `go generate` in the root directory of this repository.

## Author/Attribution

The project is a fork of [Logstash Config](https://github.com/breml/logstash-config) by Lucas Bremgartner ([breml](https://github.com/breml))

This fork adds transpile support for Elasticsearch ingest pipelines.

## License

[Apache 2.0](LICENSE)
