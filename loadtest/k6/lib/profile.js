function parseStagesJson(raw) {
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed;
    }
    if (Array.isArray(parsed?.stages)) {
      return parsed.stages;
    }
  } catch (err) {
    console.warn(`Invalid stages JSON: ${err}`);
  }
  return null;
}

export function loadStagesFromEnv() {
  return parseStagesJson(__ENV.K6_STAGES || "");
}

export function loadStagesFromProfile() {
  const profileName = __ENV.K6_PROFILE || "";
  if (!profileName) {
    return null;
  }
  const profilePath =
    __ENV.K6_PROFILE_PATH || `../profiles/${profileName}.json`;
  try {
    let resolvedPath = profilePath;
    if (!profilePath.startsWith("/") && !profilePath.startsWith("file://")) {
      resolvedPath = import.meta.resolve(profilePath);
    }
    const raw = open(resolvedPath);
    return parseStagesJson(raw);
  } catch (err) {
    console.warn(`Failed to load profile stages from ${profilePath}: ${err}`);
  }
  return null;
}

export function resolveStages(defaultStages) {
  return loadStagesFromEnv() || loadStagesFromProfile() || defaultStages;
}
