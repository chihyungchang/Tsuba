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
  shieldOff: (p: IconProps) => (
    <Svg {...p}>
      <path d="M6.2 3.9 10 2.75l6 2.25v4.6c0 1.3-.3 2.5-.85 3.6M13.9 15.3A8.6 8.6 0 0 1 10 17.25c-3.5-1.05-6-3.95-6-7.65V5.6" />
      <path d="m3 3 14 14" />
    </Svg>
  ),
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
  pause: (p: IconProps) => (
    <Svg {...p}>
      <path d="M7.25 5v10M12.75 5v10" />
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
  plus: (p: IconProps) => (
    <Svg {...p}>
      <path d="M10 4.5v11M4.5 10h11" />
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
};

export type IconName = keyof typeof Icon;
