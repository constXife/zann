export const attachErrorCause = <T extends Error>(error: T, cause: unknown): T => {
  if (cause !== undefined) {
    (error as Error & { cause?: unknown }).cause = cause;
  }
  return error;
};

export const createErrorWithCause = (message: string, cause: unknown) => {
  return attachErrorCause(new Error(message), cause);
};
