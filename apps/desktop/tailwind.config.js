/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0d0f12",
        panel: "#13161b",
        raised: "#191d23",
        line: "#242a32",
        "line-strong": "#323a44",
        fg: "#e3e7ec",
        muted: "#8b95a1",
        faint: "#5c6672",
        accent: "#4fb3a9",
        "accent-dim": "#1c3a37",
        ok: "#5fb878",
        warn: "#d9a54a",
        bad: "#e0645c",
        info: "#6aa0d8",
      },
      fontFamily: {
        sans: ['"Segoe UI Variable Text"', '"Segoe UI"', "system-ui", "sans-serif"],
        mono: ['"Cascadia Mono"', '"Cascadia Code"', "Consolas", "ui-monospace", "monospace"],
      },
      fontSize: { "2xs": ["11px", "14px"] },
      keyframes: {
        "fade-in": { from: { opacity: "0", transform: "translateY(2px)" }, to: { opacity: "1", transform: "none" } },
        pulse2: { "0%,100%": { opacity: "1" }, "50%": { opacity: ".35" } },
      },
      animation: { "fade-in": "fade-in 160ms ease-out", pulse2: "pulse2 1.6s ease-in-out infinite" },
    },
  },
  plugins: [],
};
