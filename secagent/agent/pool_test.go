package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubClient struct{}

func (stubClient) CreateChatCompletion(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	return ChatResponse{}, nil
}

func TestClientPool_Acquire(t *testing.T) {
	t.Parallel()

	t.Run("acquire_blocks_when_empty", func(t *testing.T) {
		pool := NewClientPoolWithClients([]ChatClient{stubClient{}, stubClient{}})
		ctx := t.Context()

		a1, err := pool.Acquire(ctx)
		require.NoError(t, err)
		a2, err := pool.Acquire(ctx)
		require.NoError(t, err)

		var got ChatClient
		done := make(chan struct{})
		go func() {
			got, _ = pool.Acquire(ctx)
			close(done)
		}()
		require.Never(t, func() bool {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}, 20*time.Millisecond, time.Millisecond)
		pool.Release(a1)
		<-done
		require.NotNil(t, got)
		pool.Release(a2)
		pool.Release(got)
	})

	t.Run("context_cancel", func(t *testing.T) {
		pool := NewClientPool(stubClient{}, 1)
		first, err := pool.Acquire(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err = pool.Acquire(ctx)
		require.ErrorIs(t, err, context.Canceled)
		pool.Release(first)
	})

	t.Run("nil_pool_errors", func(t *testing.T) {
		var pool *ClientPool
		_, err := pool.Acquire(t.Context())
		require.Error(t, err)
	})

	t.Run("concurrent_acquire_cap", func(t *testing.T) {
		pool := NewClientPool(stubClient{}, 2)
		var peak, current int32
		var wg sync.WaitGroup
		release := make(chan struct{})
		ctx := t.Context()
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := pool.Acquire(ctx)
				if !assert.NoError(t, err) {
					return
				}
				n := atomic.AddInt32(&current, 1)
				for {
					p := atomic.LoadInt32(&peak)
					if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
						break
					}
				}
				<-release
				atomic.AddInt32(&current, -1)
				pool.Release(c)
			}()
		}
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&current) == 2
		}, time.Second, time.Millisecond)
		close(release)
		wg.Wait()
		assert.LessOrEqual(t, peak, int32(2))
	})
}

func TestClientPool_NewClampsSize(t *testing.T) {
	t.Parallel()

	t.Run("zero_clamped_to_one", func(t *testing.T) {
		pool := NewClientPool(stubClient{}, 0)
		assert.Equal(t, 1, pool.Size())
		c, err := pool.Acquire(t.Context())
		require.NoError(t, err)
		require.NotNil(t, c)
		pool.Release(c)
	})

	t.Run("negative_clamped_to_one", func(t *testing.T) {
		pool := NewClientPool(stubClient{}, -3)
		assert.Equal(t, 1, pool.Size())
	})
}

func TestClientPool_Release(t *testing.T) {
	t.Parallel()

	t.Run("nil_pool_noop", func(t *testing.T) {
		var pool *ClientPool
		assert.NotPanics(t, func() { pool.Release(stubClient{}) })
	})

	t.Run("nil_client_noop", func(t *testing.T) {
		pool := NewClientPool(stubClient{}, 1)
		assert.NotPanics(t, func() { pool.Release(nil) })
	})
}
