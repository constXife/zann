export type ItemCategoryId =
  | "all"
  | "login"
  | "card"
  | "note"
  | "kv"
  | "infra"
  | "trash";

export const CATEGORY_TYPES: Record<Exclude<ItemCategoryId, "all" | "trash">, string[]> = {
  login: ["login"],
  card: ["card"],
  note: ["note", "identity"],
  kv: [],
  infra: ["ssh_key", "database", "cloud_iam", "server_credentials", "file_secret", "kv", "api"],
};

export const categoryForType = (typeId: string): Exclude<ItemCategoryId, "all" | "trash"> | null => {
  const entry = Object.entries(CATEGORY_TYPES).find(([, types]) => types.includes(typeId));
  if (!entry) {
    return null;
  }
  return entry[0] as Exclude<ItemCategoryId, "all" | "trash">;
};

export const categoryTypes = (categoryId: ItemCategoryId): string[] => {
  if (categoryId === "all" || categoryId === "trash") {
    return [];
  }
  return CATEGORY_TYPES[categoryId] ?? [];
};
