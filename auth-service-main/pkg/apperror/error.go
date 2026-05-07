package apperror

import coreerrors "github.com/PlatformCore/libpackage/core/errors"

func Invalid(msg string) error      { return coreerrors.New(coreerrors.CodeInvalid, msg) }
func Unauthorized(msg string) error { return coreerrors.New(coreerrors.CodeUnauthorized, msg) }
func Internal(msg string) error     { return coreerrors.New(coreerrors.CodeInternal, msg) }
func Conflict(msg string) error     { return coreerrors.New(coreerrors.CodeConflict, msg) }
