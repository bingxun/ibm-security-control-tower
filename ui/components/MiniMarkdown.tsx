"use client";

import type { ReactNode } from "react";

/**
 * Tiny, dependency-free Markdown renderer for chat/assistant text.
 * Supports: headings, bold, inline code, bullet & numbered lists, horizontal
 * rules, and paragraphs. Output is React nodes (no dangerouslySetInnerHTML),
 * so model text is never injected as HTML.
 */
function inline(text: string, key: string): ReactNode[] {
  const out: ReactNode[] = [];
  // Order matters: **bold** before *italic*; also `code`.
  const re = /(\*\*([^*]+)\*\*|\*([^*\n]+)\*|`([^`]+)`)/g;
  let last = 0, m: RegExpExecArray | null, i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    if (m[2] !== undefined) {
      out.push(<strong key={`${key}-b${i}`} style={{ color: "var(--heading)", fontWeight: 700 }}>{m[2]}</strong>);
    } else if (m[3] !== undefined) {
      out.push(<em key={`${key}-i${i}`} style={{ fontStyle: "italic" }}>{m[3]}</em>);
    } else if (m[4] !== undefined) {
      out.push(<code key={`${key}-c${i}`} className="font-mono" style={{ background: "var(--surface3)", border: "1px solid var(--border)", borderRadius: 4, padding: "1px 5px", fontSize: "0.85em" }}>{m[4]}</code>);
    }
    last = m.index + m[0].length; i++;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export default function MiniMarkdown({ text }: { text: string }) {
  const lines = text.replace(/\r/g, "").split("\n");
  const blocks: ReactNode[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;

  const flush = () => {
    if (!list) return;
    const items = list.items.map((li, k) => <li key={k}>{inline(li, `li${blocks.length}-${k}`)}</li>);
    blocks.push(
      list.ordered
        ? <ol key={`l${blocks.length}`} className="list-decimal pl-5 flex flex-col gap-1 my-0.5">{items}</ol>
        : <ul key={`l${blocks.length}`} className="list-disc pl-5 flex flex-col gap-1 my-0.5">{items}</ul>
    );
    list = null;
  };

  for (const raw of lines) {
    const t = raw.trim();
    const bullet = /^[-*]\s+(.*)$/.exec(t);
    const num = /^\d+\.\s+(.*)$/.exec(t);
    if (bullet) {
      if (list && list.ordered) flush();
      list = list ?? { ordered: false, items: [] };
      list.items.push(bullet[1]);
      continue;
    }
    if (num) {
      if (list && !list.ordered) flush();
      list = list ?? { ordered: true, items: [] };
      list.items.push(num[1]);
      continue;
    }
    flush();
    if (t === "") continue;
    if (/^---+$/.test(t) || /^___+$/.test(t)) {
      blocks.push(<hr key={`h${blocks.length}`} style={{ border: "none", borderTop: "1px solid var(--border)", margin: "8px 0" }} />);
      continue;
    }
    const h = /^(#{1,6})\s+(.*)$/.exec(t);
    if (h) {
      blocks.push(
        <div key={`t${blocks.length}`} className="font-bold" style={{ color: "var(--heading)", fontSize: h[1].length <= 2 ? "13.5px" : "12.5px", marginTop: blocks.length ? "4px" : 0 }}>
          {inline(h[2], `t${blocks.length}`)}
        </div>
      );
      continue;
    }
    blocks.push(<p key={`p${blocks.length}`} className="leading-relaxed">{inline(t, `p${blocks.length}`)}</p>);
  }
  flush();

  return <div className="flex flex-col gap-1.5">{blocks}</div>;
}
