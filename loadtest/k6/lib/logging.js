const logFailures = __ENV.K6_LOG_FAILURES === "1";
const sampleRate = Number(__ENV.K6_LOG_FAILURE_SAMPLE || "0.05");
const maxBodyLen = Number(__ENV.K6_LOG_FAILURE_BODY_LEN || "400");

export function logFailure(res, label) {
  if (!logFailures) {
    return;
  }
  if (Math.random() > sampleRate) {
    return;
  }
  const status = res?.status;
  const body = res?.body || "";
  const preview = body.length > maxBodyLen ? `${body.slice(0, maxBodyLen)}…` : body;
  console.warn(`${label} failed: status=${status} body=${preview}`);
}
