export function withName(params, name) {
  const out = params ? { ...params } : {};
  const tags = out.tags ? { ...out.tags } : {};
  tags.name = name;
  out.tags = tags;
  return out;
}
