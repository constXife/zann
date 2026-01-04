export type FieldType = "text" | "secret" | "otp" | "url" | "note";

export type FieldDef = { key: string; type: FieldType; label: string };

export type FieldSchema = { main: FieldDef[]; advanced: FieldDef[] };

export type TypeMeta = { icon: string };

const fieldSchemas: Record<string, FieldSchema> = {
  login: {
    main: [
      { key: "username", type: "text", label: "Username" },
      { key: "password", type: "secret", label: "Password" },
      { key: "url", type: "url", label: "URL" },
    ],
    advanced: [
      { key: "totp_secret", type: "otp", label: "TOTP Secret" },
      { key: "notes", type: "note", label: "Notes" },
    ],
  },
  note: {
    main: [
      { key: "title", type: "text", label: "Title" },
      { key: "text", type: "note", label: "Text" },
    ],
    advanced: [],
  },
  card: {
    main: [
      { key: "cardholder", type: "text", label: "Cardholder" },
      { key: "number", type: "secret", label: "Card Number" },
      { key: "expiry", type: "text", label: "Expiry" },
      { key: "cvv", type: "secret", label: "CVV" },
    ],
    advanced: [{ key: "notes", type: "note", label: "Notes" }],
  },
  identity: {
    main: [
      { key: "full_name", type: "text", label: "Full Name" },
      { key: "email", type: "text", label: "Email" },
      { key: "phone", type: "text", label: "Phone" },
    ],
    advanced: [{ key: "notes", type: "note", label: "Notes" }],
  },
  api: {
    main: [
      { key: "token", type: "secret", label: "Token" },
      { key: "url", type: "url", label: "URL" },
    ],
    advanced: [{ key: "notes", type: "note", label: "Notes" }],
  },
  kv: {
    main: [],
    advanced: [],
  },
};

export const typeMeta: Record<string, TypeMeta> = {
  login: { icon: "key" },
  card: { icon: "card" },
  note: { icon: "doc" },
  identity: { icon: "person" },
  api: { icon: "network" },
  kv: { icon: "list" },
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

export const getSchemaFieldDefs = (typeId: string): FieldDef[] => {
  const schema = getFieldSchema(typeId);
  return [...schema.main, ...schema.advanced];
};
