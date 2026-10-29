// Brand graphics: the sword from the App icon, the guardian sword on the dashboard, and the opening splash.
// All plain SVG with fixed colors (they are objects, so they don't follow the theme); state is shown with the halo and the scabbard.

import { useEffect, useId, useRef, useState } from "react";
import { t } from "./i18n";

/** An id usable in SVG url(#id): React's useId contains colons and similar characters, so strip them */
function useSvgId() {
  return useId().replace(/[^a-zA-Z0-9_-]/g, "");
}

/**
 * An upright katana (1024 coordinate space, tip up): curved steel blade, brass collar (habaki), black lacquer round guard (tsuba) with a gold rim, wrapped handle.
 * When sheathed the blade goes into a black lacquer scabbard: pausing protection = sheathing the sword (the scabbard slides down and settles with a jolt); resuming slides it slowly away (drawing the sword).
 * With glint, light keeps running along the blade and the temper line pulses.
 */
export function KatanaArt({ sheathed = false, glint = false }: { sheathed?: boolean; glint?: boolean }) {
  const id = useSvgId();
  const blade = "M478 568 Q462 330 526 150 L552 112 Q534 330 540 568Z";
  const wraps = [];
  for (let y = 668; y < 860; y += 40) {
    const x = 506 + (y - 640) * 0.04;
    wraps.push(<path key={y} d={`M${x - 22} ${y} L${x} ${y + 20} L${x + 22} ${y} L${x} ${y - 20}Z`} fill={`url(#${id}wrap)`} />);
  }
  return (
    <g>
      <defs>
        <linearGradient id={`${id}steel`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#8d939c" />
          <stop offset=".45" stopColor="#e9edf1" />
          <stop offset=".55" stopColor="#ffffff" />
          <stop offset="1" stopColor="#b9c0c8" />
        </linearGradient>
        <linearGradient id={`${id}brass`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#f6d98b" />
          <stop offset="1" stopColor="#a6741f" />
        </linearGradient>
        <linearGradient id={`${id}wrap`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#e8e2d4" />
          <stop offset="1" stopColor="#a59d8c" />
        </linearGradient>
        <linearGradient id={`${id}lac`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#4a4c55" />
          <stop offset="1" stopColor="#0c0d10" />
        </linearGradient>
        <linearGradient id={`${id}saya`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#0c0b0d" />
          <stop offset=".5" stopColor="#2f2a2e" />
          <stop offset="1" stopColor="#100e10" />
        </linearGradient>
        <linearGradient id={`${id}glint`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#fff" stopOpacity="0" />
          <stop offset=".5" stopColor="#fff" stopOpacity=".95" />
          <stop offset="1" stopColor="#fff" stopOpacity="0" />
        </linearGradient>
        <clipPath id={`${id}blade`}>
          <path d={blade} />
        </clipPath>
      </defs>

      <path d={blade} fill={`url(#${id}steel)`} />
      <path className={glint ? "katana-hamon" : undefined} d="M530 556 Q522 340 545 150" fill="none" stroke="#fff" strokeOpacity=".75" strokeWidth="5" />
      {glint && (
        <g clipPath={`url(#${id}blade)`} className="katana-glint-wrap">
          <rect className="katana-glint" x="430" y="520" width="160" height="150" fill={`url(#${id}glint)`} />
        </g>
      )}
      {/* The scabbard is always rendered: while protecting it hides beyond the tip; when paused it slides down over the blade.
          The outer group slides in and out, the inner one does the final jolt: both animate transform, and putting them on one element breaks the drawing transition */}
      <g className={`katana-sheath ${sheathed ? "is-on" : ""}`}>
        <g className="katana-sheath-body">
          <path d="M466 566 Q448 320 518 132 L566 104 Q546 330 552 566Z" fill={`url(#${id}saya)`} />
          <path d="M498 540 Q490 340 536 160" fill="none" stroke="#fff" strokeOpacity=".16" strokeWidth="6" />
          <path d="M520 128 L566 102 L560 132 Q540 140 522 146Z" fill={`url(#${id}brass)`} />
          <rect x="466" y="540" width="88" height="22" rx="6" fill={`url(#${id}brass)`} />
        </g>
      </g>
      <rect x="474" y="560" width="70" height="38" rx="7" fill={`url(#${id}brass)`} />
      <path d="M470 632 Q468 760 488 890 L536 890 Q548 760 548 632Z" fill="#15151a" />
      {wraps}
      <path d="M484 880 L538 880 L536 906 Q512 918 488 906Z" fill={`url(#${id}brass)`} />
      <ellipse cx="509" cy="638" rx="120" ry="40" fill="#000" opacity=".3" />
      <ellipse cx="509" cy="618" rx="120" ry="40" fill={`url(#${id}brass)`} />
      <ellipse cx="509" cy="612" rx="112" ry="34" fill={`url(#${id}lac)`} />
      <ellipse cx="490" cy="602" rx="66" ry="14" fill="#fff" opacity=".22" />
    </g>
  );
}

/** Gold dust: small specks drifting up from around the guard. Positions come from a reproducible pseudo-random sequence, so every render matches */
const DUST = (() => {
  let x = 7;
  const r = () => (x = (x * 16807) % 2147483647) / 2147483647;
  return Array.from({ length: 22 }, () => ({
    cx: 140 + (r() - 0.5) * 140,
    cy: 175 + (r() - 0.5) * 30,
    radius: 0.8 + r() * 1.8,
    duration: 3.5 + r() * 3,
    delay: -r() * 6,
    dx: (r() - 0.5) * 40,
    opacity: 0.4 + r() * 0.6,
  }));
})();

/**
 * Stops for a halo that fades out like a soft light. A two-stop radial gradient fades linearly and leaves a visible rim
 * and banding on the cream background; (1 - x²)² falls off smoothly and reaches zero with no edge.
 */
function softStops(inner: string, outer: string, peak: number) {
  return [0, 0.15, 0.3, 0.45, 0.6, 0.75, 0.9, 1].map((x) => (
    <stop key={x} offset={x} stopColor={x < 0.4 ? inner : outer} stopOpacity={(peak * (1 - x * x) ** 2).toFixed(3)} />
  ));
}

/**
 * The dashboard's guardian: a living sword with a breathing halo behind it and gold dust drifting up.
 *
 * - Protecting: the sword floats gently and light keeps running along it; the halo is gold (amber when some defenses are off).
 * - Paused: the scabbard slides down over the blade and settles, the sword sinks and dims; the halo turns dark red and the dust fades.
 * - Resuming: the scabbard slides slowly away (drawing the sword), an arc of light sweeps past as it leaves, and the sword floats again.
 * Every state's layers are always rendered and switched with transitions, so the switch itself is the animation.
 */
export function GuardianKatana({ paused, partial = false }: { paused: boolean; partial?: boolean }) {
  const id = useSvgId();
  // Play the arc of light once when resuming from pause
  const [drawKey, setDrawKey] = useState(0);
  const wasPaused = useRef(paused);
  useEffect(() => {
    if (wasPaused.current && !paused) setDrawKey((k) => k + 1);
    wasPaused.current = paused;
  }, [paused]);
  return (
    <svg className={`guardian ${paused ? "is-paused" : ""} ${partial ? "is-partial" : ""}`} viewBox="0 0 280 280" role="img" aria-label={paused ? t("Protection is paused, sword sheathed") : t("Protection is on")}>
      <defs>
        <radialGradient id={`${id}halo`} cx=".5" cy=".5" r=".5">
          {softStops(partial ? "#f0b44c" : "#f6c66a", "#ec7a45", 0.5)}
        </radialGradient>
        <radialGradient id={`${id}haloRed`} cx=".5" cy=".5" r=".5">
          {softStops("#d2452f", "#b8322a", 0.32)}
        </radialGradient>
        <linearGradient id={`${id}slash`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#fff" stopOpacity="0" />
          <stop offset=".7" stopColor="#fff6dc" />
          <stop offset="1" stopColor="#fff" />
        </linearGradient>
      </defs>
      <circle className="guardian-halo" cx="140" cy="140" r="130" fill={`url(#${id}halo)`} />
      <circle className="guardian-halo-red" cx="140" cy="140" r="130" fill={`url(#${id}haloRed)`} />
      <g className="guardian-dust">
        {DUST.map((d, i) => (
          <circle
            key={i}
            cx={d.cx.toFixed(1)}
            cy={d.cy.toFixed(1)}
            r={d.radius.toFixed(2)}
            fill="#f2cf86"
            style={{ ["--d" as string]: `${d.duration.toFixed(2)}s`, ["--delay" as string]: `${d.delay.toFixed(2)}s`, ["--dx" as string]: `${d.dx.toFixed(1)}px`, ["--o" as string]: d.opacity.toFixed(2) }}
          />
        ))}
      </g>
      <g className="guardian-sword">
        <g transform="translate(140 140) rotate(35) scale(.3) translate(-509 -512)">
          <KatanaArt sheathed={paused} glint />
        </g>
      </g>
      {drawKey > 0 && <path key={drawKey} className="guardian-slash" d="M40 210 Q140 30 250 70" fill="none" stroke={`url(#${id}slash)`} strokeWidth="5" strokeLinecap="round" strokeDasharray="420" />}
    </svg>
  );
}

/**
 * The opening splash (about 1.9 seconds), an iai draw: the sword appears sheathed, the scabbard snaps off, a slash of light
 * cuts across the screen, and the splash splits along the cut to reveal the App. The content is drawn in both halves,
 * so the sword and wordmark are cut too.
 * Not shown when the system has Reduce Motion on.
 */
export function Splash({ status }: { status: string }) {
  const [gone, setGone] = useState(() => window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  const [drawn, setDrawn] = useState(false);
  useEffect(() => {
    const draw = setTimeout(() => setDrawn(true), 380);
    const done = setTimeout(() => setGone(true), 1950);
    return () => {
      clearTimeout(draw);
      clearTimeout(done);
    };
  }, []);
  if (gone) return null;
  const content = (
    <div className="splash-content">
      <svg className="splash-sword" viewBox="0 0 280 280">
        <g transform="translate(140 140) rotate(35) scale(.3) translate(-509 -512)">
          <KatanaArt sheathed={!drawn} />
        </g>
      </svg>
      <div className="splash-word">TSUBA</div>
      <div className="splash-line">
        <span className="splash-prompt">tsuba ▸</span> <span className="splash-type">{status}</span>
      </div>
    </div>
  );
  return (
    <div className="splash" aria-hidden>
      <div className="splash-half splash-half-top">{content}</div>
      <div className="splash-half splash-half-bottom">{content}</div>
      <svg className="splash-cut" viewBox="0 0 100 100" preserveAspectRatio="none">
        <line x1="-5" y1="63.2" x2="105" y2="36.8" pathLength={1} vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="splash-flash" />
    </div>
  );
}
