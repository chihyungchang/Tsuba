// 品牌图形：和 App 图标同一把刀、首页的守护刀、打开 App 时的开场。
// 都是纯 SVG，颜色固定（它们是“器物”，不随主题换色），状态用光晕和刀鞘表达。

import { useEffect, useId, useRef, useState } from "react";

/** SVG 里 url(#id) 用的 id：React 的 useId 带冒号等字符，去掉 */
function useSvgId() {
  return useId().replace(/[^a-zA-Z0-9_-]/g, "");
}

/**
 * 一把竖直的日本刀（1024 坐标系，刀尖朝上）：有弧度的钢刃、铜套（鎺）、黑漆圆盘护手（鍔）配金边、缠绳刀柄。
 * sheathed 时刀刃收进黑漆刀鞘：暂停守护 = 刀入鞘（刀鞘滑下来，到底一顿）；恢复时刀鞘慢慢滑走（拔刀）。
 * glint 时刀刃上不停流过一道光、刃纹一明一暗。
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
      {/* 刀鞘常驻：守护中藏在刀尖外、看不见；暂停时沿刀身滑下来套住刀刃。
          外层负责滑进滑出，内层负责到底那一顿：两个都动 transform，放在同一层会让拔刀的过渡失效 */}
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

/** 金尘：护手附近往上飘的小光点。位置用可复现的伪随机算好，每次渲染一样 */
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
 * 首页的守护图：一把活着的刀，后面一团呼吸的光晕，金尘往上飘。
 *
 * - 守护中：刀轻轻浮动、刀光不停流动；光晕金色（部分防线没开时偏琥珀）。
 * - 暂停：刀鞘滑下来套住刀刃、到底一顿，刀沉下去变暗；光晕变暗红，金尘散去。
 * - 恢复：刀鞘慢慢滑走（拔刀），快离开时一道弧形刀光划过，刀重新浮起来。
 * 每种状态的图层都常驻，用过渡切换，切换本身就是动画。
 */
export function GuardianKatana({ paused, partial = false }: { paused: boolean; partial?: boolean }) {
  const id = useSvgId();
  // 从暂停恢复时触发一次弧形刀光
  const [drawKey, setDrawKey] = useState(0);
  const wasPaused = useRef(paused);
  useEffect(() => {
    if (wasPaused.current && !paused) setDrawKey((k) => k + 1);
    wasPaused.current = paused;
  }, [paused]);
  return (
    <svg className={`guardian ${paused ? "is-paused" : ""} ${partial ? "is-partial" : ""}`} viewBox="0 0 280 280" role="img" aria-label={paused ? "守护已暂停，刀已入鞘" : "守护中"}>
      <defs>
        <radialGradient id={`${id}halo`} cx=".5" cy=".5" r=".5">
          <stop offset="0" stopColor={partial ? "#f0b44c" : "#f6c66a"} stopOpacity=".55" />
          <stop offset=".45" stopColor="#e5532f" stopOpacity=".18" />
          <stop offset="1" stopColor="#e5532f" stopOpacity="0" />
        </radialGradient>
        <radialGradient id={`${id}haloRed`} cx=".5" cy=".5" r=".5">
          <stop offset="0" stopColor="#7a1d16" stopOpacity=".5" />
          <stop offset="1" stopColor="#7a1d16" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={`${id}slash`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#fff" stopOpacity="0" />
          <stop offset=".7" stopColor="#fff6dc" />
          <stop offset="1" stopColor="#fff" />
        </linearGradient>
      </defs>
      <circle className="guardian-halo" cx="140" cy="140" r="130" fill={`url(#${id}halo)`} />
      <circle className="guardian-halo-red" cx="140" cy="140" r="120" fill={`url(#${id}haloRed)`} />
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

/** 朱红圆角方块里的刀：开场画面和大尺寸品牌标志用（和 App 图标同一个样子） */
export function KatanaIcon({ size = 120 }: { size?: number }) {
  const id = useSvgId();
  return (
    <svg width={size} height={size} viewBox="0 0 1024 1024" aria-hidden>
      <defs>
        <linearGradient id={`${id}bg`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#e8582f" />
          <stop offset="1" stopColor="#9c2411" />
        </linearGradient>
      </defs>
      <rect x="40" y="40" width="944" height="944" rx="210" fill={`url(#${id}bg)`} />
      <g transform="translate(530 494) rotate(35) scale(1.02) translate(-509 -512)">
        <KatanaArt />
      </g>
    </svg>
  );
}

/**
 * 打开 App 时的开场（约 1.2 秒）：刀标弹出，下面像终端一样打出状态，四段依次点亮，然后淡出。
 * 系统开了“减少动态效果”时不显示。
 */
export function Splash({ status }: { status: string }) {
  const [gone, setGone] = useState(() => window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    const t = setTimeout(() => setGone(true), 1500);
    return () => clearTimeout(t);
  }, []);
  if (gone) return null;
  return (
    <div className="splash" aria-hidden>
      <div className="splash-icon">
        <KatanaIcon size={132} />
      </div>
      <div className="splash-line">
        <span className="splash-prompt">tsuba ▸</span> <span className="splash-type">{status}</span>
        <span className="splash-cursor" />
      </div>
      <div className="splash-steps">
        <span />
        <span />
        <span />
        <span />
      </div>
    </div>
  );
}
