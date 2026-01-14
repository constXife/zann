export function authHeaders(token) {
  if (!token) {
    return {};
  }
  return buildHeaders({ token, testRunId: __ENV.ZANN_TEST_RUN_ID });
}

export function buildHeaders({ token, requestId, testRunId, extraHeaders } = {}) {
  const headers = {};
  if (requestId) {
    headers["X-Request-Id"] = requestId;
  }
  if (testRunId) {
    headers.baggage = `zann.test_run_id=${testRunId}`;
  }
  if (extraHeaders) {
    Object.assign(headers, extraHeaders);
  }
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return { headers };
}
