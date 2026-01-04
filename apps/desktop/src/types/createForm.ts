export type Translator = (key: string, params?: Record<string, unknown>) => string;

export type FieldInput = {
  id: string;
  key: string;
  value: string;
  fieldType: "text" | "secret" | "otp" | "url" | "note";
  isCustom: boolean;
  isSecret: boolean;
};
