import sharedFieldSchemas from "../../../../schemas/item_fields.json";

export type FieldType = "text" | "secret" | "otp" | "url" | "note";

export type FieldDef = { key: string; type: FieldType; label: string };

export type FieldSchema = { main: FieldDef[]; advanced: FieldDef[] };

export type TypeMeta = { icon: string };

const fieldSchemas = sharedFieldSchemas as Record<string, FieldSchema>;

export const typeMeta: Record<string, TypeMeta> = {
  login: { icon: "key" },
  card: { icon: "card" },
  note: { icon: "doc" },
  identity: { icon: "person" },
  api: { icon: "network" },
  kv: { icon: "list" },
  ssh_key: { icon: "key" },
  database: { icon: "list" },
  cloud_iam: { icon: "network" },
  file_secret: { icon: "doc" },
  server_credentials: { icon: "key" },
};

export const jsonPlaceholders: Record<string, string> = {
  login:
    "{\n  \"v\": 1,\n  \"typeId\": \"login\",\n  \"fields\": {\n    \"username\": { \"kind\": \"text\", \"value\": \"alice\" },\n    \"password\": { \"kind\": \"password\", \"value\": \"...\" }\n  }\n}",
  card:
    "{\n  \"v\": 1,\n  \"typeId\": \"card\",\n  \"fields\": {\n    \"cardholder\": { \"kind\": \"text\", \"value\": \"Alice\" },\n    \"number\": { \"kind\": \"password\", \"value\": \"4111...\" }\n  }\n}",
  note:
    "{\n  \"v\": 1,\n  \"typeId\": \"note\",\n  \"fields\": {\n    \"title\": { \"kind\": \"text\", \"value\": \"Meeting notes\" },\n    \"text\": { \"kind\": \"note\", \"value\": \"...\" }\n  }\n}",
  identity:
    "{\n  \"v\": 1,\n  \"typeId\": \"identity\",\n  \"fields\": {\n    \"first_name\": { \"kind\": \"text\", \"value\": \"Alice\" },\n    \"email\": { \"kind\": \"text\", \"value\": \"alice@example.com\" }\n  }\n}",
  api:
    "{\n  \"v\": 1,\n  \"typeId\": \"api\",\n  \"fields\": {\n    \"name\": { \"kind\": \"text\", \"value\": \"Staging\" },\n    \"token\": { \"kind\": \"password\", \"value\": \"...\" }\n  }\n}",
  kv:
    "{\n  \"v\": 1,\n  \"typeId\": \"kv\",\n  \"fields\": {\n    \"region\": { \"kind\": \"text\", \"value\": \"us-east-1\" },\n    \"token\": { \"kind\": \"password\", \"value\": \"...\" }\n  }\n}",
  ssh_key:
    "{\n  \"v\": 1,\n  \"typeId\": \"ssh_key\",\n  \"fields\": {\n    \"private_key\": { \"kind\": \"password\", \"value\": \"...\" },\n    \"public_key\": { \"kind\": \"text\", \"value\": \"ssh-rsa AAA...\" }\n  }\n}",
  database:
    "{\n  \"v\": 1,\n  \"typeId\": \"database\",\n  \"fields\": {\n    \"host\": { \"kind\": \"text\", \"value\": \"10.0.0.5\" },\n    \"port\": { \"kind\": \"text\", \"value\": \"5432\" }\n  }\n}",
  cloud_iam:
    "{\n  \"v\": 1,\n  \"typeId\": \"cloud_iam\",\n  \"fields\": {\n    \"access_key\": { \"kind\": \"text\", \"value\": \"AKIA...\" },\n    \"secret_key\": { \"kind\": \"password\", \"value\": \"...\" }\n  }\n}",
  file_secret:
    "{\n  \"v\": 1,\n  \"typeId\": \"file_secret\",\n  \"fields\": {\n    \"file_id\": { \"kind\": \"text\", \"value\": \"uuid\" },\n    \"upload_state\": { \"kind\": \"text\", \"value\": \"ready\" }\n  },\n  \"extra\": {\n    \"filename\": \"secret.bin\"\n  }\n}",
  server_credentials:
    "{\n  \"v\": 1,\n  \"typeId\": \"server_credentials\",\n  \"fields\": {\n    \"host\": { \"kind\": \"text\", \"value\": \"10.0.0.5\" },\n    \"username\": { \"kind\": \"text\", \"value\": \"root\" }\n  }\n}",
  default:
    "{\n  \"v\": 1,\n  \"typeId\": \"custom\",\n  \"fields\": {\n    \"field\": { \"kind\": \"text\", \"value\": \"value\" }\n  }\n}",
};

export const getFieldSchema = (typeId: string): FieldSchema =>
  fieldSchemas[typeId] ?? { main: [], advanced: [] };

export const getSchemaKeys = (typeId: string): string[] => {
  const schema = getFieldSchema(typeId);
  return [...schema.main, ...schema.advanced].map((field) => field.key);
};

export const getSchemaLabel = (typeId: string, key: string): string | null => {
  const schema = getFieldSchema(typeId);
  const def = [...schema.main, ...schema.advanced].find((field) => field.key === key);
  return def?.label ?? null;
};

export const resolveSchemaLabel = (
  t: (key: string) => string,
  typeId: string,
  key: string,
): string => {
  const label = getSchemaLabel(typeId, key) ?? key;
  if (!label.startsWith("fields.")) {
    return label;
  }
  const translated = t(label);
  return translated === label ? key : translated;
};

export const getSchemaFieldDefs = (typeId: string): FieldDef[] => {
  const schema = getFieldSchema(typeId);
  return [...schema.main, ...schema.advanced];
};
