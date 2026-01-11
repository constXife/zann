export type FieldType = "text" | "secret" | "otp" | "url" | "note";

export type FieldDef = { key: string; type: FieldType; label: string };

export type FieldSchema = { main: FieldDef[]; advanced: FieldDef[] };

export type TypeMeta = { icon: string };

const fieldSchemas: Record<string, FieldSchema> = {
  login: {
    main: [
      { key: "username", type: "text", label: "fields.username" },
      { key: "password", type: "secret", label: "fields.password" },
      { key: "url", type: "url", label: "fields.url" },
    ],
    advanced: [
      { key: "totp_secret", type: "otp", label: "fields.totp_secret" },
      { key: "notes", type: "note", label: "fields.notes" },
    ],
  },
  note: {
    main: [
      { key: "title", type: "text", label: "fields.title" },
      { key: "text", type: "note", label: "fields.text" },
    ],
    advanced: [],
  },
  card: {
    main: [
      { key: "cardholder", type: "text", label: "fields.cardholder" },
      { key: "number", type: "secret", label: "fields.card_number" },
      { key: "expiry", type: "text", label: "fields.expiry" },
      { key: "cvv", type: "secret", label: "fields.cvv" },
    ],
    advanced: [{ key: "notes", type: "note", label: "fields.notes" }],
  },
  identity: {
    main: [
      { key: "full_name", type: "text", label: "fields.full_name" },
      { key: "email", type: "text", label: "fields.email" },
      { key: "phone", type: "text", label: "fields.phone" },
    ],
    advanced: [{ key: "notes", type: "note", label: "fields.notes" }],
  },
  api: {
    main: [
      { key: "token", type: "secret", label: "fields.token" },
      { key: "url", type: "url", label: "fields.url" },
    ],
    advanced: [{ key: "notes", type: "note", label: "fields.notes" }],
  },
  kv: {
    main: [],
    advanced: [],
  },
  ssh_key: {
    main: [
      { key: "private_key", type: "secret", label: "fields.private_key" },
      { key: "public_key", type: "text", label: "fields.public_key" },
      { key: "passphrase", type: "secret", label: "fields.passphrase" },
      { key: "username", type: "text", label: "fields.username" },
    ],
    advanced: [{ key: "notes", type: "note", label: "fields.notes" }],
  },
  database: {
    main: [
      { key: "host", type: "text", label: "fields.host" },
      { key: "port", type: "text", label: "fields.port" },
      { key: "user", type: "text", label: "fields.user" },
      { key: "password", type: "secret", label: "fields.password" },
      { key: "database", type: "text", label: "fields.database" },
      { key: "driver", type: "text", label: "fields.driver" },
    ],
    advanced: [{ key: "notes", type: "note", label: "fields.notes" }],
  },
  cloud_iam: {
    main: [
      { key: "access_key", type: "text", label: "fields.access_key" },
      { key: "secret_key", type: "secret", label: "fields.secret_key" },
      { key: "region", type: "text", label: "fields.region" },
      { key: "role", type: "text", label: "fields.role_scope" },
    ],
    advanced: [{ key: "notes", type: "note", label: "fields.notes" }],
  },
  file_secret: {
    main: [
      { key: "file_id", type: "text", label: "fields.file_id" },
      { key: "upload_state", type: "text", label: "fields.upload_state" },
      { key: "filename", type: "text", label: "fields.filename" },
      { key: "mime", type: "text", label: "fields.mime" },
      { key: "size", type: "text", label: "fields.size" },
      { key: "checksum", type: "text", label: "fields.checksum" },
    ],
    advanced: [{ key: "notes", type: "note", label: "fields.notes" }],
  },
  server_credentials: {
    main: [
      { key: "host", type: "text", label: "fields.host" },
      { key: "username", type: "text", label: "fields.username" },
      { key: "password", type: "secret", label: "fields.password" },
      { key: "protocol", type: "text", label: "fields.protocol" },
    ],
    advanced: [{ key: "notes", type: "note", label: "fields.notes" }],
  },
};

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
