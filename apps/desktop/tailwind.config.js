/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{vue,ts}"],
  darkMode: "class",
  theme: {
    extend: {
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      colors: {
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        surface: {
          "light-1": "#f5f5f7",
          "light-2": "#ffffff",
          "light-3": "#e5e5e7",
          "dark-1": "#1c1c1e",
          "dark-2": "#2c2c2e",
          "dark-3": "#3c3c3e",
        },
        category: {
          all: "#007AFF",
          login: "#007AFF",
          note: "#FFCC00",
          card: "#FF2D55",
          identity: "#5856D6",
          api: "#00C7BE",
          kv: "#64D2FF",
          security: "#FF3B30",
        },
        apple: {
          blue: "#007AFF",
          "blue-dark": "#0A84FF",
          gray: "#8e8e93",
          "gray-2": "#636366",
          "gray-3": "#48484a",
          "gray-4": "#3a3a3c",
          "gray-5": "#2c2c2e",
          "gray-6": "#1c1c1e",
        },
      },
    },
  },
  plugins: [],
};
