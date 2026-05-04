package orchestrator

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalToolArgs(t *testing.T) {
	t.Parallel()

	type planEntry struct {
		WorkerID   int    `json:"worker_id"`
		Assignment string `json:"assignment"`
	}
	type planArgs struct {
		Plans []planEntry `json:"plans"`
	}
	type singleArgs struct {
		Plan planEntry `json:"plan"`
	}
	type scalarArgs struct {
		WorkerID int    `json:"worker_id"`
		Reason   string `json:"reason"`
	}

	t.Run("happy_path_object", func(t *testing.T) {
		var got planArgs
		err := unmarshalToolArgs(json.RawMessage(`{"plans":[{"worker_id":1,"assignment":"x"}]}`), &got)
		require.NoError(t, err)
		require.Len(t, got.Plans, 1)
		assert.Equal(t, 1, got.Plans[0].WorkerID)
	})

	t.Run("happy_path_scalars", func(t *testing.T) {
		var got scalarArgs
		err := unmarshalToolArgs(json.RawMessage(`{"worker_id":3,"reason":"done"}`), &got)
		require.NoError(t, err)
		assert.Equal(t, 3, got.WorkerID)
		assert.Equal(t, "done", got.Reason)
	})

	t.Run("recovers_string_encoded_array", func(t *testing.T) {
		var got planArgs
		err := unmarshalToolArgs(json.RawMessage(
			`{"plans":"[{\"worker_id\":1,\"assignment\":\"a\"},{\"worker_id\":2,\"assignment\":\"b\"}]"}`,
		), &got)
		require.NoError(t, err)
		require.Len(t, got.Plans, 2)
		assert.Equal(t, "a", got.Plans[0].Assignment)
		assert.Equal(t, 2, got.Plans[1].WorkerID)
	})

	t.Run("recovers_object_into_array_field", func(t *testing.T) {
		var got planArgs
		err := unmarshalToolArgs(json.RawMessage(
			`{"plans":"{\"worker_id\":7,\"assignment\":\"solo\"}"}`,
		), &got)
		require.NoError(t, err)
		require.Len(t, got.Plans, 1)
		assert.Equal(t, 7, got.Plans[0].WorkerID)
		assert.Equal(t, "solo", got.Plans[0].Assignment)
	})

	t.Run("wraps_single_object_into_array", func(t *testing.T) {
		var got planArgs
		err := unmarshalToolArgs(json.RawMessage(
			`{"plans":{"worker_id":4,"assignment":"single"}}`,
		), &got)
		require.NoError(t, err)
		require.Len(t, got.Plans, 1)
		assert.Equal(t, 4, got.Plans[0].WorkerID)
	})

	t.Run("recovers_into_struct_field", func(t *testing.T) {
		var got singleArgs
		err := unmarshalToolArgs(json.RawMessage(
			`{"plan":"{\"worker_id\":9,\"assignment\":\"deep dive\"}"}`,
		), &got)
		require.NoError(t, err)
		assert.Equal(t, 9, got.Plan.WorkerID)
		assert.Equal(t, "deep dive", got.Plan.Assignment)
	})

	t.Run("unwraps_array_into_struct", func(t *testing.T) {
		var got singleArgs
		err := unmarshalToolArgs(json.RawMessage(
			`{"plan":[{"worker_id":11,"assignment":"unwrap me"}]}`,
		), &got)
		require.NoError(t, err)
		assert.Equal(t, 11, got.Plan.WorkerID)
	})

	t.Run("returns_original_error_on_garbage", func(t *testing.T) {
		var got planArgs
		err := unmarshalToolArgs(json.RawMessage(`{"plans":"not parseable"}`), &got)
		require.Error(t, err)
	})

	t.Run("errors_on_wrong_shape", func(t *testing.T) {
		var got planArgs
		err := unmarshalToolArgs(json.RawMessage(`"just a string"`), &got)
		require.Error(t, err)
	})

	t.Run("ignores_unrelated_extra_fields", func(t *testing.T) {
		var got planArgs
		err := unmarshalToolArgs(json.RawMessage(
			`{"plans":[{"worker_id":1,"assignment":"x"}],"extra":"ignored"}`,
		), &got)
		require.NoError(t, err)
		require.Len(t, got.Plans, 1)
	})
}
