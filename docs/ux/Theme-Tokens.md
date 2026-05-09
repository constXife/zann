# Theme Tokens (Light and Dark) - zann

Goal: capture the current desktop (Tauri) color tokens as the baseline for other clients.

## Light Theme Tokens

**Base (HSL)**
- background: 240 5% 96%
- foreground: 240 5% 12%
- primary: 211 100% 50%
- primary-foreground: 0 0% 100%
- muted: 240 5% 90%
- muted-foreground: 240 4% 55%
- destructive: 4 100% 59%
- destructive-foreground: 0 0% 100%
- border: 240 4% 84%
- input: 240 4% 84%
- ring: 211 100% 50%
- popover: 0 0% 100%
- popover-foreground: 240 5% 12%

**Surface + Text (hex/rgba)**
- bg-primary: #f5f5f7
- bg-secondary: #ffffff
- bg-tertiary: #e5e5e7
- bg-hover: rgba(0, 0, 0, 0.05)
- bg-active: rgba(0, 0, 0, 0.1)
- text-primary: #1c1c1e
- text-secondary: #8e8e93
- text-tertiary: #c7c7cc
- border-color: rgba(0, 0, 0, 0.1)
- accent: #007AFF
- accent-hover: #0066d6
- accent-active: #005bbf
- radius: 0.5rem

## Dark Theme Tokens

**Base (HSL)**
- background: 240 5% 12%
- foreground: 0 0% 100%
- primary: 207 100% 52%
- primary-foreground: 0 0% 100%
- muted: 240 5% 22%
- muted-foreground: 240 4% 65%
- destructive: 4 100% 59%
- destructive-foreground: 0 0% 100%
- border: 240 5% 30%
- input: 240 5% 30%
- ring: 207 100% 52%
- popover: 240 5% 18%
- popover-foreground: 0 0% 100%

**Surface + Text (hex/rgba)**
- bg-primary: #1c1c1e
- bg-secondary: #2c2c2e
- bg-tertiary: #3c3c3e
- bg-hover: rgba(255, 255, 255, 0.05)
- bg-active: rgba(255, 255, 255, 0.1)
- text-primary: #ffffff
- text-secondary: #8e8e93
- text-tertiary: #6b6b70
- border-color: rgba(255, 255, 255, 0.1)
- accent: #0A84FF
- accent-hover: #1a8fff
- accent-active: #0071e3
- radius: 0.5rem

## Category Colors

- all: #007AFF
- login: #007AFF
- note: #FFCC00
- card: #FF2D55
- identity: #5856D6
- api: #00C7BE
- kv: #64D2FF
- infra: #34C759
- ssh_key: #34C759
- database: #34C759
- cloud_iam: #34C759
- file_secret: #34C759
- server_credentials: #34C759
- security: #FF3B30

## Notes

- The desktop app sets `color-scheme: light dark` and uses class-based dark mode.
- Accent values are hex-defined in the CSS variables (effective values above).
