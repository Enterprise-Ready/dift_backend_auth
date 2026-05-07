package retry

import (
	"context"
	"time"

	engretry "github.com/PlatformCore/libpackage/resilience/retry"
)

func Do(ctx context.Context, fn func(context.Context) error) error {
	cfg := engretry.DefaultConfig()
	cfg.MaxAttempts = 3
	cfg.InitialDelay = 50 * time.Millisecond
	cfg.MaxDelay = 500 * time.Millisecond
	return engretry.Do(ctx, cfg, fn).Err
}
