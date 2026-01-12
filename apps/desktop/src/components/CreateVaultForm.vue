<script setup lang="ts">
import type { Translator } from "../types/createForm";
import { CachePolicy, VaultKind } from "../constants/enums";

const createVaultName = defineModel<string>("createVaultName", { required: true });
const createVaultKind = defineModel<VaultKind>("createVaultKind", { required: true });
const createVaultCachePolicy = defineModel<CachePolicy>("createVaultCachePolicy", { required: true });
const createVaultDefault = defineModel<boolean>("createVaultDefault", { required: true });

const props = defineProps<{ t: Translator }>();
</script>

<template>
  <div class="mt-4 space-y-4">
    <label class="block space-y-1 text-sm">
      <span class="flex items-center justify-between gap-2">
        <span class="font-medium">{{ props.t("create.vaultName") }}</span>
        <span
          v-if="createVaultKind === VaultKind.Shared"
          class="rounded-full bg-category-security/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-category-security"
        >
          {{ props.t("create.kindShared") }}
        </span>
      </span>
      <input
        v-model="createVaultName"
        type="text"
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
        spellcheck="false"
        class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
        :placeholder="props.t('create.vaultName')"
        data-testid="create-vault-name"
      />
    </label>
    <label class="block space-y-1 text-sm">
      <span class="font-medium">{{ props.t("create.cachePolicy") }}</span>
      <select
        v-model="createVaultCachePolicy"
        class="w-full rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
      >
        <option :value="CachePolicy.Full">{{ props.t("create.cacheFull") }}</option>
        <option :value="CachePolicy.MetadataOnly">{{ props.t("create.cacheMetadata") }}</option>
        <option :value="CachePolicy.None">{{ props.t("create.cacheNone") }}</option>
      </select>
    </label>
    <label class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
      <input type="checkbox" class="rounded" v-model="createVaultDefault" />
      <span>{{ props.t("create.setDefault") }}</span>
    </label>
  </div>
</template>
