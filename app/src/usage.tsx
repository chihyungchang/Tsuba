import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { lang, t, type Lang } from "./i18n";
import { Config } from "./types";
import { errText } from "./ui";

// The product site's locale for each UI language; English has none
const SITE_LOCALES: Partial<Record<Lang, string>> = { "zh-Hans": "zh", "zh-Hant": "zh-hant", ja: "ja", ko: "ko", es: "es", fr: "fr", de: "de", "pt-BR": "pt-br", ru: "ru" };

/** Tsuba's privacy notice on the product site, in the UI language */
export function privacyUrl(): string {
  const locale = SITE_LOCALES[lang()];
  return `https://oliverz.dev${locale ? `/${locale}` : ""}/products/tsuba/privacy`;
}

/** Sends nothing itself: the backend reports (src-tauri/src/usage_stats.rs), and only once this was answered */
export function setUsageStats(on: boolean): Promise<void> {
  return invoke("set_usage_stats", { on });
}

/**
 * The first-launch notice about the anonymous usage stats: what they are and that nothing personal is sent in one line,
 * the full list one click away (Settings → Privacy), one click turns them off. It stays until answered, and nothing is
 * sent before then. A protection tool earns trust by asking plainly, so the notice never hides behind a dismiss button.
 */
export function UsageNotice({ details }: { details: () => void }) {
  const [isShown, setShown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const refresh = () => invoke<Config>("get_config").then((c) => setShown(!c.has_seen_usage_notice)).catch(() => {});
    refresh();
    // Answered in Settings → Privacy instead
    const off = listen("status-changed", refresh);
    return () => {
      off.then((f) => f());
    };
  }, []);
  if (!isShown) return null;

  const answer = async (on: boolean) => {
    setBusy(true);
    try {
      await setUsageStats(on);
      setShown(false);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="usage-notice" role="dialog" aria-label={t("Help improve Tsuba")}>
      <strong>{t("Help improve Tsuba")}</strong>
      <p>
        {t("Tsuba sends anonymous counts, such as how many checks it ran. Never your commands, files or anything personal.")}{" "}
        <button className="link" onClick={details}>
          {t("Details")}
        </button>
      </p>
      {error && <p className="usage-notice-error">{error}</p>}
      <div className="usage-notice-actions">
        <button onClick={() => answer(false)} disabled={busy}>
          {t("Turn Off")}
        </button>
        <button className="primary" onClick={() => answer(true)} disabled={busy}>
          {t("OK")}
        </button>
      </div>
    </div>
  );
}
