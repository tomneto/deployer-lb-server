// Package conf carries the managed vhost template INSIDE the binary.
//
// It exists because template and binary used to be two independently
// delivered artifacts: `setup.sh` installs `nginx-app.conf.tmpl` into
// /etc/nginx/lb-templates/, and the binary is downloaded separately by the
// fleet's auto-update. Nothing kept them in step.
//
// That gap is not cosmetic. `text/template` has no tolerance for a field it
// does not know: a template that references `.OrderedLocations` executed by a
// binary built before that method exists fails at Execute. runApplyLocked
// turns a render error into a 400, and lb_sync_worker marks a 400 FAILED with
// no retry — so one stale file would silently break EVERY apply on that host,
// for every pipeline, until a human noticed.
//
// With the template compiled in, the two cannot disagree. A path override
// still exists for someone deliberately testing a different template, and the
// listener renders a probe payload at boot and refuses to start if it fails —
// so a broken override is found at startup, where the fleet's canary halts the
// rollout, instead of on the next apply of a production vhost.
//
// The file stays at conf/nginx-app.conf.tmpl, as the single source: setup.sh
// still installs it for humans to read, and the golden tests still render it
// from disk. This package only embeds it; it does not copy it.
package conf

import _ "embed"

// NginxAppTemplate is conf/nginx-app.conf.tmpl, compiled into the binary.
//
//go:embed nginx-app.conf.tmpl
var NginxAppTemplate string
