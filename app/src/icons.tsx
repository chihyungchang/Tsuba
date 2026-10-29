// Line icons for the UI: one 20×20 canvas, 1.5 stroke width, round caps, color follows the text.
// Drawn by hand rather than taken from an icon library: there are few of them, and they stay in the brand mark's style.

import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 18, children, ...rest }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      {...rest}
    >
      {children}
    </svg>
  );
}

/**
 * Silhouette of a katana laid diagonally (64 × 64): curved blade, round guard (tsuba), handle.
 * The same sword as the App icon; the menu bar template icon icons/tray-template.png has this shape too.
 */
export function KatanaGlyph({ fill }: { fill: string }) {
  return (
    <g transform="rotate(35 32 32)" fill={fill}>
      <path d="M28.6 36Q27.2 21 31.8 8.4L34.6 4.8Q33.4 21 34.4 36Z" />
      <ellipse cx="31.5" cy="38.4" rx="10.5" ry="5.4" />
      <path d="M28.4 41.6Q28.3 50 29.8 59.4L33.8 59.4Q35 50 35 41.6Z" />
    </g>
  );
}

/** Brand mark: a white sword in a vermilion rounded square, same look as the App icon. */
export function TsubaMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden>
      <rect x="1" y="1" width="62" height="62" rx="15" fill="var(--brand)" />
      <g transform="translate(32 32) scale(.8) translate(-32 -32)">
        <KatanaGlyph fill="#fff" />
      </g>
    </svg>
  );
}

export const Icon = {
  overview: (p: IconProps) => (
    <Svg {...p}>
      <path d="M10 2.75 4 5v4.6c0 3.7 2.5 6.6 6 7.65 3.5-1.05 6-3.95 6-7.65V5l-6-2.25z" />
      <path d="m7.5 10 1.8 1.8 3.4-3.6" />
    </Svg>
  ),
  /** A shield struck through: protection is paused */
  trash: (p: IconProps) => (
    <Svg {...p}>
      <path d="M3.5 5.5h13M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M5.5 5.5l.7 10.1a1.5 1.5 0 0 0 1.5 1.4h4.6a1.5 1.5 0 0 0 1.5-1.4l.7-10.1M8.5 8.5v5.5M11.5 8.5v5.5" />
    </Svg>
  ),
  history: (p: IconProps) => (
    <Svg {...p}>
      <path d="M3.5 5.5h13M3.5 10h13M3.5 14.5h8" />
    </Svg>
  ),
  scan: (p: IconProps) => (
    <Svg {...p}>
      <path d="M3 6.5V5a2 2 0 0 1 2-2h1.5M13.5 3H15a2 2 0 0 1 2 2v1.5M17 13.5V15a2 2 0 0 1-2 2h-1.5M6.5 17H5a2 2 0 0 1-2-2v-1.5" />
      <path d="M3 10h14" />
    </Svg>
  ),
  doctor: (p: IconProps) => (
    <Svg {...p}>
      <path d="M2.5 10h3l2-4.5 3.5 9 2-4.5h4.5" />
    </Svg>
  ),
  settings: (p: IconProps) => (
    <Svg {...p}>
      <path d="M4 5.5h7M15 5.5h1M4 14.5h2M10 14.5h6" />
      <circle cx="13" cy="5.5" r="1.75" />
      <circle cx="8" cy="14.5" r="1.75" />
    </Svg>
  ),
  terminal: (p: IconProps) => (
    <Svg {...p}>
      <rect x="2.75" y="3.75" width="14.5" height="12.5" rx="2.25" />
      <path d="m6 8 2 2-2 2M10.5 12.5H14" />
    </Svg>
  ),
  package: (p: IconProps) => (
    <Svg {...p}>
      <path d="m10 2.75 6.25 3.4v7.7L10 17.25l-6.25-3.4v-7.7L10 2.75z" />
      <path d="M3.9 6.2 10 9.6l6.1-3.4M10 9.6v7.5" />
    </Svg>
  ),
  extension: (p: IconProps) => (
    <Svg {...p}>
      <path d="M8 3.5h-3a1.5 1.5 0 0 0-1.5 1.5v3h1a1.75 1.75 0 1 1 0 3.5h-1V15a1.5 1.5 0 0 0 1.5 1.5h3v-1a1.75 1.75 0 1 1 3.5 0v1H15a1.5 1.5 0 0 0 1.5-1.5v-3h-1a1.75 1.75 0 1 1 0-3.5h1V5A1.5 1.5 0 0 0 15 3.5h-3.5v1a1.75 1.75 0 1 1-3.5 0v-1z" />
    </Svg>
  ),
  plug: (p: IconProps) => (
    <Svg {...p}>
      <path d="M7.5 2.75v3.5M12.5 2.75v3.5M5 6.25h10v2.5a5 5 0 0 1-10 0v-2.5zM10 13.75v3.5" />
    </Svg>
  ),
  brain: (p: IconProps) => (
    <Svg {...p}>
      <circle cx="10" cy="10" r="2.25" />
      <path d="M10 2.75v2.5M10 14.75v2.5M2.75 10h2.5M14.75 10h2.5M4.9 4.9l1.75 1.75M13.35 13.35l1.75 1.75M4.9 15.1l1.75-1.75M13.35 6.65l1.75-1.75" />
    </Svg>
  ),
  folder: (p: IconProps) => (
    <Svg {...p}>
      <path d="M2.75 6.25a1.5 1.5 0 0 1 1.5-1.5h3.4l1.6 1.75h6.5a1.5 1.5 0 0 1 1.5 1.5v6.75a1.5 1.5 0 0 1-1.5 1.5H4.25a1.5 1.5 0 0 1-1.5-1.5v-8.5z" />
    </Svg>
  ),
  lock: (p: IconProps) => (
    <Svg {...p}>
      <rect x="4" y="8.75" width="12" height="8.5" rx="2" />
      <path d="M6.75 8.75V6.5a3.25 3.25 0 0 1 6.5 0v2.25" />
    </Svg>
  ),
  check: (p: IconProps) => (
    <Svg {...p}>
      <path d="m4.5 10.5 3.5 3.5 7.5-8" />
    </Svg>
  ),
  alert: (p: IconProps) => (
    <Svg {...p}>
      <path d="M10 3.25 17.25 16H2.75L10 3.25z" />
      <path d="M10 8.25v3.25M10 13.9v.1" />
    </Svg>
  ),
  stop: (p: IconProps) => (
    <Svg {...p}>
      <path d="M7 2.75h6L17.25 7v6L13 17.25H7L2.75 13V7L7 2.75z" />
      <path d="m7.75 7.75 4.5 4.5M12.25 7.75l-4.5 4.5" />
    </Svg>
  ),
  play: (p: IconProps) => (
    <Svg {...p}>
      <path d="M6.5 4.5v11l9-5.5-9-5.5z" />
    </Svg>
  ),
  chevron: (p: IconProps) => (
    <Svg {...p}>
      <path d="m8 5 5 5-5 5" />
    </Svg>
  ),
  arrowDown: (p: IconProps) => (
    <Svg {...p}>
      <path d="M10 3.5v11M5.5 10l4.5 4.5 4.5-4.5M4 17h12" />
    </Svg>
  ),
  refresh: (p: IconProps) => (
    <Svg {...p}>
      <path d="M16 10a6 6 0 1 1-1.8-4.3M16 3.75V6.5h-2.75" />
    </Svg>
  ),
  globe: (p: IconProps) => (
    <Svg {...p}>
      <circle cx="10" cy="10" r="7.25" />
      <path d="M2.75 10h14.5M10 2.75c2 2 3 4.4 3 7.25s-1 5.25-3 7.25c-2-2-3-4.4-3-7.25s1-5.25 3-7.25z" />
    </Svg>
  ),
  bell: (p: IconProps) => (
    <Svg {...p}>
      <path d="M5.25 7.5a4.75 4.75 0 0 1 9.5 0c0 3.5 1.5 5 1.5 5H3.75s1.5-1.5 1.5-5zM8.25 15.25a1.9 1.9 0 0 0 3.5 0" />
    </Svg>
  ),
  /** GitHub's mark is a filled shape, so it overrides the line style */
  github: ({ size = 18, ...rest }: IconProps) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden {...rest}>
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
  ),
  /** Claude's spark, in Claude's orange: marks the judgment mode when Claude Code or the Claude API makes the call */
  claude: ({ size = 18, ...rest }: IconProps) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="#d97757" strokeWidth={1.4} strokeLinecap="round" aria-hidden {...rest}>
      <path d="M9.58 8.22L14.54 8.92M9.26 8.99L12.10 11.20M8.60 9.48L10.47 14.12M7.78 9.58L7.28 13.15M7.01 9.26L3.94 13.20M6.52 8.60L3.18 9.95M6.42 7.78L1.46 7.08M6.74 7.01L3.90 4.80M7.40 6.52L5.53 1.88M8.22 6.42L8.72 2.85M8.99 6.74L12.06 2.80M9.48 7.40L12.82 6.05" />
    </svg>
  ),
  /** OpenAI's knot, for Codex and the OpenAI preset; filled, so it follows the text color */
  openai: ({ size = 18, ...rest }: IconProps) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden {...rest}>
      <path d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z" />
    </svg>
  ),
  /** Gemini's four-pointed sparkle, in its blue */
  gemini: ({ size = 18, ...rest }: IconProps) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="#4f7ff0" aria-hidden {...rest}>
      <path d="M12 1C12 7.08 16.92 12 23 12C16.92 12 12 16.92 12 23C12 16.92 7.08 12 1 12C7.08 12 12 7.08 12 1Z" />
    </svg>
  ),
  external: (p: IconProps) => (
    <Svg {...p}>
      <path d="M11.5 3.75h4.75V8.5M16.25 3.75 9.5 10.5M14.25 11.5v3.25a1.5 1.5 0 0 1-1.5 1.5h-7.5a1.5 1.5 0 0 1-1.5-1.5v-7.5a1.5 1.5 0 0 1 1.5-1.5H8.5" />
    </Svg>
  ),
};

export type IconName = keyof typeof Icon;
