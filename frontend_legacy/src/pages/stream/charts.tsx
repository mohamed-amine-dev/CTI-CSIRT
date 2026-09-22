export function Sparkline({
  data,
  w = 560,
  h = 110,
}: {
  data: { t: number; n: number }[];
  w?: number;
  h?: number;
}) {
  if (data.length < 2) {
    return <div className="flex h-full items-center justify-center text-sm text-faint">Not enough points</div>;
  }
  const max = Math.max(1, ...data.map((d) => d.n));
  const px = (i: number) => (i / (data.length - 1)) * w;
  const py = (v: number) => h - 6 - (v / max) * (h - 14);
  const pts = data.map((d, i) => `${px(i).toFixed(1)},${py(d.n).toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-full w-full">
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
    </svg>
  );
}