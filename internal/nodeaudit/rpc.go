package nodeaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/blocktack/blocktack/internal/core"
)

var rpcClient = &http.Client{Timeout: 15 * time.Second}

// rpcEndpoints returns the target's RPC endpoints.
func rpcEndpoints(tgt *core.Target) []core.Endpoint {
	var out []core.Endpoint
	for _, ep := range tgt.Endpoints {
		if ep.Role == "" || ep.Role == "rpc" {
			out = append(out, ep)
		}
	}
	return out
}

// rawRPC posts an arbitrary body (possibly malformed JSON) and returns
// the HTTP status and response body. Used by the fuzz battery, where a
// JSON-RPC error response is a *good* outcome.
func rawRPC(ctx context.Context, url string, body []byte) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rpcClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(data), nil
}

// rpcCall performs a well-formed JSON-RPC call.
func rpcCall(ctx context.Context, url, method string, params any) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	status, respBody, err := rawRPC(ctx, url, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("http %d: %.200s", status, respBody)
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(respBody), &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

func clientVersion(ctx context.Context, url string) (string, error) {
	res, err := rpcCall(ctx, url, "web3_clientVersion", []any{})
	if err != nil {
		return "", err
	}
	var v string
	if err := json.Unmarshal(res, &v); err != nil {
		return "", fmt.Errorf("decode clientVersion: %w", err)
	}
	return v, nil
}
