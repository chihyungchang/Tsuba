// 品牌图形：和 App 图标同一把刀、首页的刀镡状态环、打开 App 时的开场。
// 都是纯 SVG，颜色固定（它们是“器物”，不随主题换色），状态用外圈和刀鞘表达。

import { useEffect, useId, useRef, useState } from "react";

/** SVG 里 url(#id) 用的 id：React 的 useId 带冒号等字符，去掉 */
function useSvgId() {
  return useId().replace(/[^a-zA-Z0-9_-]/g, "");
}

/**
 * 一把竖直的日本刀（1024 坐标系，刀尖朝上）：有弧度的钢刃、铜套（鎺）、黑漆圆盘护手（鍔）配金边、缠绳刀柄。
 * sheathed 时刀刃收进黑漆刀鞘：暂停守护 = 刀入鞘（刀鞘滑下来，有过渡动画）。glint 时刀刃上每隔几秒掠过一道光；
 * drawKey 每变一次，刀刃闪一下（恢复守护 = 拔刀出鞘）。
 */
export function KatanaArt({ sheathed = false, glint = false, drawKey = 0 }: { sheathed?: boolean; glint?: boolean; drawKey?: number }) {
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
      <path d="M530 556 Q522 340 545 150" fill="none" stroke="#fff" strokeOpacity=".7" strokeWidth="4" />
      {glint && (
        <g clipPath={`url(#${id}blade)`} className="katana-glint-wrap">
          <rect className="katana-glint" x="430" y="560" width="160" height="120" fill={`url(#${id}glint)`} />
          {drawKey > 0 && <rect key={drawKey} className="katana-draw-flash" x="430" y="100" width="160" height="480" fill="#fff" />}
        </g>
      )}
      {/* 刀鞘常驻：守护中藏在刀尖外、看不见；暂停时沿刀身滑下来套住刀刃 */}
      <g className={`katana-sheath ${sheathed ? "is-on" : ""}`}>
        <path d="M466 566 Q448 320 518 132 L566 104 Q546 330 552 566Z" fill={`url(#${id}saya)`} />
        <path d="M498 540 Q490 340 536 160" fill="none" stroke="#fff" strokeOpacity=".16" strokeWidth="6" />
        <path d="M520 128 L566 102 L560 132 Q540 140 522 146Z" fill={`url(#${id}brass)`} />
        <rect x="466" y="540" width="88" height="22" rx="6" fill={`url(#${id}brass)`} />
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

export type Defense = { label: string; on: boolean };

/**
 * 首页的刀镡状态环：正面看的护手圆盘，盘面刻着青海波纹，中间穿过一把刀；外圈四段对应四道防线。
 *
 * 动效都表达状态：守护中一颗光点绕外圈走、外圈呼吸、刀光不时掠过；
 * 暂停时刀鞘滑下来套住刀刃，外圈一段接一段由金变红，整个环轻轻一沉；恢复时刀鞘滑走、刀刃一闪，外圈依次亮回金色。
 * 每种状态的图层都常驻，用过渡切换，所以切换本身就是动画。
 */
export function TsubaRing({ defenses, paused }: { defenses: Defense[]; paused: boolean }) {
  const id = useSvgId();
  const cx = 120;
  const cy = 120;
  // 从暂停恢复的那一刻刀刃闪一下
  const [drawKey, setDrawKey] = useState(0);
  const wasPaused = useRef(paused);
  useEffect(() => {
    if (wasPaused.current && !paused) setDrawKey((k) => k + 1);
    wasPaused.current = paused;
  }, [paused]);

  const arc = (i: number, r = 108) => {
    const a0 = -90 + i * 90 + 7;
    const a1 = a0 + 76;
    const p = (a: number) => [cx + r * Math.cos((a * Math.PI) / 180), cy + r * Math.sin((a * Math.PI) / 180)];
    const [x0, y0] = p(a0);
    const [x1, y1] = p(a1);
    return `M${x0.toFixed(1)} ${y0.toFixed(1)}A${r} ${r} 0 0 1 ${x1.toFixed(1)} ${y1.toFixed(1)}`;
  };
  const active = defenses.filter((d) => d.on).length;
  return (
    <svg className={`tsuba-ring ${paused ? "is-paused" : ""}`} viewBox="0 0 240 240" role="img" aria-label={paused ? "守护已暂停" : `${active} 道防线在工作`}>
      <defs>
        <linearGradient id={`${id}gold`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#f6dc9b" />
          <stop offset=".5" stopColor="#d8b36a" />
          <stop offset="1" stopColor="#9c7128" />
        </linearGradient>
        <radialGradient id={`${id}disc`} cx=".4" cy=".3" r=".85">
          <stop offset="0" stopColor="#36343c" />
          <stop offset="1" stopColor="#0f0e12" />
        </radialGradient>
        <radialGradient id={`${id}discRed`} cx=".4" cy=".3" r=".85">
          <stop offset="0" stopColor="#4a1a16" />
          <stop offset="1" stopColor="#1c0d0c" />
        </radialGradient>
        <radialGradient id={`${id}comet`} cx=".5" cy=".5" r=".5">
          <stop offset="0" stopColor="#fff6dc" />
          <stop offset=".4" stopColor="#f6dc9b" stopOpacity=".9" />
          <stop offset="1" stopColor="#d8b36a" stopOpacity="0" />
        </radialGradient>
        {/* 青海波：一排排同心半圆，刻在盘面上 */}
        <pattern id={`${id}wave`} width="16" height="8" patternUnits="userSpaceOnUse">
          {[7.5, 5, 2.5].map((r) => (
            <g key={r} fill="none" stroke="#d8b36a" strokeWidth=".6">
              <path d={`M${8 - r} 8a${r} ${r} 0 0 1 ${2 * r} 0`} />
              <path d={`M${-r} 4a${r} ${r} 0 0 1 ${2 * r} 0`} />
              <path d={`M${16 - r} 4a${r} ${r} 0 0 1 ${2 * r} 0`} />
            </g>
          ))}
        </pattern>
        <clipPath id={`${id}clip`}>
          <circle cx={cx} cy={cy} r="84" />
        </clipPath>
        <filter id={`${id}glow`} x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="3.2" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <g className="ring-body">
        {/* 外圈：每段一层暗底、一层金、一层红；切换时逐段交叉淡入淡出 */}
        {defenses.map((d, i) => (
          <g key={d.label} className={`ring-seg ${d.on ? "is-on" : ""}`} style={{ ["--i" as string]: i }}>
            <title>{`${d.label}：${paused ? "已暂停" : d.on ? "在工作" : "没有开启"}`}</title>
            <path d={arc(i)} fill="none" stroke="var(--ring-off)" strokeWidth="9" strokeLinecap="round" />
            <path className="seg-gold" d={arc(i)} fill="none" stroke={`url(#${id}gold)`} strokeWidth="9" strokeLinecap="round" filter={`url(#${id}glow)`} />
            <path className="seg-red" d={arc(i)} fill="none" stroke="#c42a1d" strokeWidth="9" strokeLinecap="round" strokeDasharray="10 8" />
          </g>
        ))}
        {/* 绕着外圈走的一颗光点：守护中的“心跳” */}
        <g className="ring-comet">
          <circle cx={cx} cy={cy - 108} r="9" fill={`url(#${id}comet)`} />
        </g>

        <circle cx={cx} cy={cy} r="84" fill={`url(#${id}disc)`} />
        <circle className="disc-red" cx={cx} cy={cy} r="84" fill={`url(#${id}discRed)`} />
        <g clipPath={`url(#${id}clip)`} className="ring-waves-wrap">
          <rect className="ring-waves" x="20" y="20" width="200" height="200" fill={`url(#${id}wave)`} />
        </g>
        <circle cx={cx} cy={cy} r="84" fill="none" stroke={`url(#${id}gold)`} strokeOpacity=".6" strokeWidth="1.5" />
        <circle cx={cx} cy={cy} r="71" fill="none" stroke="#fff" strokeOpacity=".05" />
        <g transform={`translate(${cx} ${cy}) rotate(35) scale(.182) translate(-509 -512)`}>
          <KatanaArt sheathed={paused} glint drawKey={drawKey} />
        </g>
      </g>
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
