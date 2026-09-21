# DESIGN.md — SENTINEL AI Threat Intelligence Gateway

## 1. Product Context & Purpose
- **Product Name**: SENTINEL AI — Threat Intelligence Gateway
- **Domain**: Cyber Defense & Security Operations Center (SOC) Threat Analysis
- **Target Audience**: Cybersecurity Analysts, SOC Incident Responders, Security Researchers, and Vigilant Web Users evaluating suspicious URLs, raw email bodies, and MIME headers.
- **Primary Job to be Done**: Analyze potential phishing vectors, extract technical & social engineering threat indicators, calculate verifiable risk scores, and generate actionable incident response guidance.
- **Trust Requirement**: Absolute. The UI must feel authoritative, precise, transparent, and operational — like professional cybersecurity tooling (e.g. CrowdStrike, VirusTotal Enterprise, Splunk Enterprise Security) — not a generic marketing SaaS.

---

## 2. UX Character (Observable Qualities)
1. **Tactical & High-Density**: Information is presented in organized data grids, tabular metrics, and technical inspectors with minimal decorative whitespace padding.
2. **Deterministic & Transparent**: Clear distinction between local deterministic rule-based heuristics and AI-assisted deep semantic evaluation.
3. **High-Contrast Precision**: Critical threats pop instantly in alert red (`#FF3366`), warnings in warning amber (`#FFB800`), and clean assets in verified green (`#00E699`) against a dark slate tactical background (`#080C14`).
4. **Accessible & Keyboard-First**: Full keyboard navigation support with explicit high-contrast focus rings (`focus-visible`), aria labels, and `Ctrl + Enter` execution shortcuts.

---

## 3. Visual Direction & Design Tokens

### 3.1 Typography Scale
- **Header & Display Font**: `Plus Jakarta Sans` (weights: 600, 700, 800)
- **Body & UI Font**: `Plus Jakarta Sans` (weights: 400, 500)
- **Telemetry & Technical Font**: `JetBrains Mono` (weights: 400, 500, 700)

#### Type Hierarchy Tokens:
- `Display` (Page Header): `20px` / `24px` | `Plus Jakarta Sans 700` | uppercase, tracked
- `H1` (Console Section Title): `16px` / `20px` | `Plus Jakarta Sans 700`
- `H2` (Card / Box Header): `14px` / `18px` | `Plus Jakarta Sans 600`
- `Body` (Main Text): `13px` / `18px` | `Plus Jakarta Sans 400`
- `Caption / Monospace Telemetry`: `11px` / `16px` | `JetBrains Mono 400` | tabular numbers
- `Badge / Label`: `10px` / `14px` | `JetBrains Mono 700` | uppercase, tracked

### 3.2 Color Tokens (SOC Palette)
```css
/* Background & Surfaces */
--color-bg-root: #080c14;
--color-surface-base: #0f172a;
--color-surface-panel: #131c31;
--color-surface-elevated: #1a243d;

/* Borders & Separators */
--color-border-subtle: rgba(255, 255, 255, 0.08);
--color-border-tactical: rgba(255, 255, 255, 0.15);
--color-border-active: #00f0ff;

/* Text Tiers */
--color-text-primary: #f8fafc;
--color-text-secondary: #94a3b8;
--color-text-muted: #64748b;

/* Threat Severity Semantics */
--color-threat-danger: #ff3366;
--color-threat-warning: #ffb800;
--color-threat-safe: #00e699;
--color-threat-info: #00f0ff;
```

### 3.3 Layout & Grid Rhythm
- **Density**: Compact padding (`px-3 py-2.5` to `px-4 py-3.5`).
- **Corner Radius**: Sharp `rounded-md` (4px to 6px). No hyper-rounded pills or `rounded-3xl` cards.
- **Grid Layout**: 12-column responsive layout:
  - Left Console (5 cols): Input Vector Tabs + History Vault
  - Right Inspector (7 cols): Global Metrics Banner + Threat Radar + Detailed Inspector (Risk Gauge, Signal Breakdown, AI Report)

---

## 4. Forbidden Anti-References (Guardrails)
❌ **No Generic Purple/Blue Gradients**: Avoid standard landing-page mesh gradients. Use solid tactical slate with subtle glowing alert borders.  
❌ **No Card-in-Card Nesting**: Contain content using crisp border grid lines and distinct surface shades rather than stacking multiple rounded cards.  
❌ **No Floating Blobs / Decorative Orbs**: Every visual element must serve a operational diagnostic purpose.  
❌ **No Generic SaaS Copy**: Replace "Supercharge your security" with technical SOC terminology ("EXECUTE THREAT SCAN", "MIME HEADER DECODER", "AUTHENTICATE OPERATOR").  
❌ **No Missing Interaction States**: Every button and input must have idle, hover, active, focus-visible, and disabled states.

---

## 5. Accessibility & Motion Guidelines
- **Focus Rings**: `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#00F0FF] focus-visible:ring-offset-2 focus-visible:ring-offset-[#080C14]`.
- **Contrast**: Text contrast ratio >= 4.5:1 against surfaces.
- **Motion**: Minimal transitions (150ms-250ms ease-out) for tab switches and scan progress updates. Respect `prefers-reduced-motion`.
