// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"net/http"

	"github.com/PharosVPN/coxswain/internal/audit"
)

// audited writes an audit entry for an API mutation, filling the actor and
// source IP from the request. action is the dotted verb; targetType/targetID
// identify the affected record (targetID may be empty when the action failed
// before a record existed); detail is optional action-specific context; err is
// non-nil for a failed mutation (the row is marked result=error). The DB-write
// error is intentionally ignored — auditing must never break the request it
// records (the failure is still emitted to slog).
func (s *Server) audited(r *http.Request, action, targetType, targetID string, detail map[string]any, err error) {
	a := audit.ActorFrom(r.Context())
	_ = audit.Log(r.Context(), s.db, audit.Entry{
		Actor:      a.Name,
		ActorKind:  a.Kind,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		SourceIP:   audit.SourceIP(r),
		Detail:     detail,
		Err:        err,
	})
}
