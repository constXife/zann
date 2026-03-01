<script setup lang="ts">
import { computed, useAttrs } from "vue";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../../lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center rounded-lg font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-1 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-[var(--accent)] text-white hover:opacity-90",
        secondary: "bg-transparent text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]",
        destructive: "bg-category-security text-white hover:opacity-90",
        warning: "bg-amber-500 text-white hover:bg-amber-400",
        outline: "border border-[var(--border-color)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]",
        ghost: "hover:bg-[var(--bg-hover)] text-[var(--text-secondary)]",
        link: "underline-offset-4 hover:underline text-[var(--accent)]",
      },
      size: {
        default: "h-10 px-4 py-2 text-sm",
        sm: "h-9 px-3 py-2 text-sm",
        xs: "h-7 px-2.5 py-1 text-xs",
        lg: "h-11 px-6 py-3 text-sm",
        icon: "h-9 w-9",
        "icon-sm": "h-7 w-7",
        "icon-xs": "h-6 w-6",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

type ButtonVariants = VariantProps<typeof buttonVariants>;

const props = withDefaults(
  defineProps<{
    variant?: ButtonVariants["variant"];
    size?: ButtonVariants["size"];
    type?: "button" | "submit" | "reset";
    loading?: boolean;
    fullWidth?: boolean;
  }>(),
  {
    variant: "default",
    size: "default",
    type: "button",
    loading: false,
    fullWidth: false,
  },
);

const attrs = useAttrs();
const classes = computed(() =>
  cn(
    buttonVariants({ variant: props.variant, size: props.size }),
    props.fullWidth && "w-full",
    attrs.class,
  ),
);
const passthrough = computed(() => {
  const { class: _class, ...rest } = attrs as Record<string, unknown>;
  return rest;
});
</script>

<template>
  <button :type="type" v-bind="passthrough" :class="classes" :disabled="loading || ($attrs.disabled as boolean)">
    <svg
      v-if="loading"
      class="mr-2 h-4 w-4 animate-spin"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
    <slot />
  </button>
</template>
