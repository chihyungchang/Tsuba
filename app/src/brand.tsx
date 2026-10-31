// Brand graphics: the dashboard guardian (the guard on a laptop's screen) and the opening splash.
// The guard and the laptop are Blender renders (src-tauri/icons/source/tsuba.py, laptop.py) with the same materials and
// light as the App icon. Fixed colors (they are objects, so they don't follow the theme); state is shown with the halo and the screen.

import { useEffect, useId, useRef, useState } from "react";
import laptopArt from "./assets/laptop.png";
import tsubaArt from "./assets/tsuba.png";
import { t } from "./i18n";
import { GUARD_HOLES } from "./icons";

/** An id usable in SVG url(#id): React's useId contains colons and similar characters, so strip them */
function useSvgId() {
  return useId().replace(/[^a-zA-Z0-9_-]/g, "");
}

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
 * Code scrolling on the laptop's screen: rows of token bars (widths in % of the screen). A fixed list, so every render matches;
 * drawn twice so the scroll loops without a seam. "risk" tokens are the ones a check would flag.
 */
const CODE_ROWS: [number, "plain" | "key" | "risk"][][] = [
  [[14, "key"], [30, "plain"]],
  [[6, "plain"], [22, "plain"], [12, "key"]],
  [[6, "plain"], [38, "risk"]],
  [[20, "key"], [16, "plain"]],
  [[6, "plain"], [12, "plain"], [26, "plain"]],
  [[10, "key"], [34, "plain"]],
  [[6, "plain"], [18, "plain"], [8, "risk"]],
  [[24, "plain"], [10, "key"]],
];

/** The guard's art on screen, with a band of light sweeping across it (the sheen is masked to the guard's shape) */
function GuardArt({ className }: { className: string }) {
  const mask = `url(${tsubaArt}) center / contain no-repeat`;
  return (
    <div className={className}>
      <img src={tsubaArt} alt="" draggable={false} />
      <div className="guard-sheen" style={{ WebkitMask: mask, mask }} />
    </div>
  );
}

/** A hooded figure with glowing eyes, lit red from below by the screen: what gets in while the guard is away */
function Hacker({ id }: { id: string }) {
  return (
    <svg className="guardian-hacker" viewBox="0 0 100 100" aria-hidden>
      <defs>
        <linearGradient id={`${id}hood`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#3a3d47" />
          <stop offset=".55" stopColor="#17181d" />
          <stop offset="1" stopColor="#0b0b0e" />
        </linearGradient>
        <radialGradient id={`${id}face`} cx=".5" cy=".7" r=".6">
          <stop offset="0" stopColor="#3b0d08" />
          <stop offset="1" stopColor="#050506" />
        </radialGradient>
      </defs>
      {/* Shoulders, then the hood with a red rim light where the screen catches it */}
      <path d="M6 100 C10 78 26 70 50 70 C74 70 90 78 94 100Z" fill={`url(#${id}hood)`} />
      <path d="M50 10 C29 10 21 30 22 50 C23 64 30 76 50 80 C70 76 77 64 78 50 C79 30 71 10 50 10Z" fill={`url(#${id}hood)`} stroke="#ff5a3c" strokeOpacity=".5" strokeWidth="1.2" />
      <path d="M50 28 C38 28 33 39 33 50 C33 62 40 70 50 71 C60 70 67 62 67 50 C67 39 62 28 50 28Z" fill={`url(#${id}face)`} />
      <g className="guardian-hacker-eyes" fill="#ff6b4a">
        <path d="M38 47 L46 49.5 L45 52 L38 50.5Z" />
        <path d="M62 47 L54 49.5 L55 52 L62 50.5Z" />
      </g>
    </svg>
  );
}

/**
 * The dashboard's guardian: a laptop with the guard standing on its screen, in front of the code that runs there.
 *
 * - Protecting: the screen is calm, code scrolls and a gold line keeps scanning it; the guard stands in front of it like a
 *   shield, glowing, floating and swaying in 3D with light sweeping across it. The halo is gold (amber when some defenses are off).
 * - Paused: the guard steps back out of sight, the screen turns red and a hooded hacker rises into it, glitching.
 * - Resuming: the hacker drops away, the guard comes forward with a little overshoot and a gold ring bursts out from it.
 * Every state's layers are always rendered and switched with transitions, so the switch itself is the animation.
 */
export function GuardianTsuba({ paused, partial = false }: { paused: boolean; partial?: boolean }) {
  const id = useSvgId();
  // Play the ring once when resuming from pause
  const [resumeKey, setResumeKey] = useState(0);
  const wasPaused = useRef(paused);
  useEffect(() => {
    if (wasPaused.current && !paused) setResumeKey((k) => k + 1);
    wasPaused.current = paused;
  }, [paused]);
  const rows = [...CODE_ROWS, ...CODE_ROWS];
  return (
    <div className={`guardian ${paused ? "is-paused" : ""} ${partial ? "is-partial" : ""}`} role="img" aria-label={paused ? t("Protection is paused, nothing guards the screen") : t("Protection is on")}>
      <svg className="guardian-halo-layer" viewBox="0 0 280 280" aria-hidden>
        <defs>
          <radialGradient id={`${id}halo`} cx=".5" cy=".5" r=".5">
            {softStops(partial ? "#f0b44c" : "#f6c66a", "#ec7a45", 0.5)}
          </radialGradient>
          <radialGradient id={`${id}haloRed`} cx=".5" cy=".5" r=".5">
            {softStops("#d2452f", "#b8322a", 0.32)}
          </radialGradient>
        </defs>
        <circle className="guardian-halo" cx="140" cy="120" r="130" fill={`url(#${id}halo)`} />
        <circle className="guardian-halo-red" cx="140" cy="120" r="130" fill={`url(#${id}haloRed)`} />
      </svg>
      <div className="guardian-stage">
        <img className="guardian-laptop" src={laptopArt} alt="" draggable={false} />
        <div className="guardian-screen">
        <div className="guardian-code">
          {rows.map((row, i) => (
            <div key={i} className="guardian-code-row">
              {row.map(([width, kind], j) => (
                <span key={j} className={`is-${kind}`} style={{ width: `${width}%` }} />
              ))}
            </div>
          ))}
        </div>
        <div className="guardian-scan" />
        <div className="guardian-alarm" />
        <Hacker id={id} />
        <div className="guardian-shield" />
        <GuardArt className="guardian-guard" />
        {resumeKey > 0 && <div key={resumeKey} className="guardian-ring" />}
        </div>
      </div>
    </div>
  );
}

/**
 * The opening splash (about 1.8 seconds): the guard rises out of the dark, light from the App shows through its three
 * holes, then the view rushes into the tang hole and the App opens out of it.
 *
 * The dark is one huge shape with the guard's holes cut out, drawn in the same SVG as the guard, so they zoom together and
 * the App is only ever seen through the holes. The holes are cut a little inside the render's, which reads as the iron's depth.
 * Not shown when the system has Reduce Motion on.
 */
export function Splash({ status }: { status: string }) {
  const id = useSvgId();
  const [gone, setGone] = useState(() => window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    const done = setTimeout(() => setGone(true), 1850);
    return () => clearTimeout(done);
  }, []);
  if (gone) return null;
  return (
    <div className="splash" aria-hidden>
      <svg className="splash-guard" viewBox="0 0 1024 1024">
        <defs>
          <radialGradient id={`${id}dark`} gradientUnits="userSpaceOnUse" cx="512" cy="512" r="2400">
            <stop offset="0" stopColor="#2a1d17" />
            <stop offset=".6" stopColor="#141216" />
            <stop offset="1" stopColor="#0d0c0f" />
          </radialGradient>
        </defs>
        <path d={`M-60000 -60000H61024V61024H-60000Z${GUARD_HOLES}`} transform="translate(512 512) scale(.94) translate(-512 -512)" fill={`url(#${id}dark)`} fillRule="evenodd" />
        {/* The art spans 1.42 Blender units on a 2-unit, 1024-pixel icon canvas: 727 pixels, centered */}
        <image className="splash-art" href={tsubaArt} x="148.5" y="148.5" width="727" height="727" />
      </svg>
      <div className="splash-text">
        <div className="splash-word">TSUBA</div>
        <div className="splash-line">
          <span className="splash-prompt">tsuba ▸</span> <span className="splash-type">{status}</span>
        </div>
      </div>
    </div>
  );
}
