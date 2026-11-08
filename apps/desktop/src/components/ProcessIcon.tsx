import { AppWindow, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../lib/api";

const cache = new Map<string, string | null>();

/** Real shell icon of the executable, or a neutral placeholder when the
 *  path is unknown (no access) or the file has no icon. */
export function ProcessIcon({ path, denied, size = 16 }: { path: string | null; denied?: boolean; size?: number }) {
  const [src, setSrc] = useState<string | null>(path ? (cache.get(path) ?? null) : null);
  useEffect(() => {
    if (!path || cache.has(path)) {
      setSrc(path ? (cache.get(path) ?? null) : null);
      return;
    }
    let alive = true;
    api
      .processIcon(path)
      .then((d) => {
        cache.set(path, d);
        if (alive) setSrc(d);
      })
      .catch(() => cache.set(path, null));
    return () => {
      alive = false;
    };
  }, [path]);
  if (src) return <img src={src} width={size} height={size} alt="" className="shrink-0" draggable={false} />;
  const Icon = denied ? ShieldAlert : AppWindow;
  return <Icon size={size} className="shrink-0 text-faint" />;
}
