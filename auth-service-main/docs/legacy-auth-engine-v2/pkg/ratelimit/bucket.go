//go:build legacy
// +build legacy

package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenBucket implements a distributed token bucket rate limiter using Redis
type TokenBucket struct {
	rdb *redis.Client
}

func NewTokenBucket(rdb *redis.Client) *TokenBucket {
	return &TokenBucket{rdb: rdb}
}

type Result struct {
	Allowed    bool
	Remaining  int64
	ResetAfter time.Duration
	RetryAfter time.Duration
}

// Allow checks if action is allowed for the given key
// capacity: max tokens, rate: tokens per second, tokens: cost of this request
func (tb *TokenBucket) Allow(ctx context.Context, key string, capacity int, rate float64, tokens int) (*Result, error) {
	now := time.Now().Unix()
	script := redis.NewScript(`
		local key = KEYS[1]
		local capacity = tonumber(ARGV[1])
		local rate = tonumber(ARGV[2])
		local tokens = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])

		local bucket = redis.call("HMGET", key, "tokens", "last_refill")
		local current_tokens = tonumber(bucket[1]) or capacity
		local last_refill = tonumber(bucket[2]) or now

		-- Refill tokens
		local elapsed = now - last_refill
		local refill = math.floor(elapsed * rate)
		current_tokens = math.min(capacity, current_tokens + refill)

		local allowed = 0
		if current_tokens >= tokens then
			current_tokens = current_tokens - tokens
			allowed = 1
		end

		redis.call("HMSET", key, "tokens", current_tokens, "last_refill", now)
		redis.call("EXPIRE", key, math.ceil(capacity / rate) + 1)

		return {allowed, current_tokens}
	`)

	result, err := script.Run(ctx, tb.rdb,
		[]string{fmt.Sprintf("tb:%s", key)},
		capacity, rate, tokens, now,
	).Slice()
	if err != nil {
		return &Result{Allowed: true}, err // fail open
	}

	allowed := result[0].(int64) == 1
	remaining := result[1].(int64)

	resetAfter := time.Duration(float64(int64(capacity)-remaining)/rate) * time.Second
	retryAfter := time.Duration(float64(int64(tokens)-remaining)/rate) * time.Second

	return &Result{
		Allowed:    allowed,
		Remaining:  remaining,
		ResetAfter: resetAfter,
		RetryAfter: retryAfter,
	}, nil
}

// SlidingWindow checks requests in a sliding time window
func (tb *TokenBucket) SlidingWindow(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	now := time.Now()
	windowStart := now.Add(-window).UnixMilli()
	nowMs := now.UnixMilli()

	pipe := tb.rdb.Pipeline()
	rkey := fmt.Sprintf("sw:%s", key)

	pipe.ZRemRangeByScore(ctx, rkey, "0", fmt.Sprintf("%d", windowStart))
	pipe.ZAdd(ctx, rkey, redis.Z{Score: float64(nowMs), Member: fmt.Sprintf("%d-%s", nowMs, key)})
	pipe.ZCard(ctx, rkey)
	pipe.Expire(ctx, rkey, window)

	results, err := pipe.Exec(ctx)
	if err != nil {
		return &Result{Allowed: true}, err
	}

	count := results[2].(*redis.IntCmd).Val()
	allowed := count <= int64(limit)
	remaining := int64(limit) - count
	if remaining < 0 {
		remaining = 0
	}

	return &Result{
		Allowed:    allowed,
		Remaining:  remaining,
		ResetAfter: window,
		RetryAfter: window / time.Duration(limit),
	}, nil
}

// FixedWindow - simplest approach, atomic with Redis INCR
func (tb *TokenBucket) FixedWindow(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	rkey := fmt.Sprintf("fw:%s:%d", key, time.Now().Truncate(window).Unix())

	pipe := tb.rdb.Pipeline()
	incr := pipe.Incr(ctx, rkey)
	pipe.Expire(ctx, rkey, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return &Result{Allowed: true}, err
	}

	count := incr.Val()
	allowed := count <= int64(limit)
	remaining := int64(limit) - count
	if remaining < 0 {
		remaining = 0
	}

	return &Result{
		Allowed:    allowed,
		Remaining:  remaining,
		ResetAfter: window,
	}, nil
}
