import React, { useMemo, useState } from 'react';
import { geoGraticule10, geoNaturalEarth1, geoPath, interpolate, max, scaleSequential } from 'd3';
import { feature } from 'topojson-client';
import world from 'world-atlas/countries-110m.json';

import { numericCountryId } from '../../utils/countryCodes';
import { compactNumber } from '../../utils/format';

// Fixed logical viewBox; the SVG scales to any container width.
const VIEW_W = 960;
const VIEW_H = 500;

/**
 * ChoroplethMap — D3 threat-origin map (Natural Earth projection).
 *
 * Paints each country by the number of indicator IPs geolocated to it
 * (data from /api/v1/geo/summary). world-atlas keys features by ISO numeric
 * country id; ipwho.is reports alpha-2 — joined via utils/countryCodes.js.
 * Clicking a country drills into the filtered IOC list view.
 */
export default function ChoroplethMap({ countries = [], total = 0, onSelect, height = 520 }) {
  const [hover, setHover] = useState(null);

  const features = useMemo(() => feature(world, world.objects.countries).features, []);

  const { path, color } = useMemo(() => {
    const projection = geoNaturalEarth1().fitExtent(
      [
        [10, 10],
        [VIEW_W - 10, VIEW_H - 10],
      ],
      { type: 'FeatureCollection', features },
    );
    const maxCount = max(countries.map((c) => c.count)) || 0;
    return {
      path: geoPath(projection),
      color: scaleSequential()
        .domain([1, maxCount || 1])
        .interpolator(interpolate('#155e75', '#22d3ee')),
    };
  }, [features, countries]);

  const countByNum = useMemo(() => {
    const map = new Map();
    for (const c of countries) {
      const nid = numericCountryId(c.code);
      if (nid) map.set(nid, c.count);
    }
    return map;
  }, [countries]);

  const nameByNum = useMemo(() => {
    const map = new Map();
    for (const f of features) map.set(String(f.id), f.properties.name);
    return map;
  }, [features]);

  const graticule = useMemo(() => geoGraticule10(), []);
  const graticulePath = useMemo(() => path(graticule), [path]);

  return (
    <div className="relative" style={{ height }}>
      <svg
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        className="h-full w-full"
        role="img"
        aria-label="Threat origin map by country"
      >
        <path d={path({ type: 'Sphere' })} fill="#0a1120" stroke="rgb(var(--color-line))" strokeWidth={1} />
        <path d={graticulePath} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth={0.5} />
        {features.map((f) => {
          const count = countByNum.get(String(f.id)) || 0;
          const isHover = hover && hover.id === String(f.id);
          return (
            <path
              key={f.id}
              d={path(f)}
              fill={count > 0 ? color(count) : '#16203a'}
              stroke={isHover ? '#22d3ee' : 'rgb(var(--color-line))'}
              strokeWidth={isHover ? 1.5 : 0.5}
              style={{ cursor: count > 0 ? 'pointer' : 'default', transition: 'fill 120ms' }}
              onMouseMove={(e) => {
                const rect = e.currentTarget.ownerSVGElement.getBoundingClientRect();
                setHover({
                  id: String(f.id),
                  name: nameByNum.get(String(f.id)) || f.properties.name,
                  count,
                  x: e.clientX - rect.left,
                  y: e.clientY - rect.top,
                });
              }}
              onMouseLeave={() => setHover(null)}
              onClick={() => {
                const code = countries.find((c) => numericCountryId(c.code) === String(f.id))?.code;
                if (count > 0 && code && onSelect) onSelect(code, nameByNum.get(String(f.id)) || f.properties.name);
              }}
            />
          );
        })}
      </svg>

      {hover && hover.count > 0 && (
        <div
          className="pointer-events-none absolute z-10 rounded-lg border border-line bg-base/95 px-3 py-2 shadow-xl"
          style={{
            left: Math.min(hover.x + 12, VIEW_W - 200),
            top: Math.min(hover.y + 12, VIEW_H - 70),
          }}
        >
          <p className="text-xs font-semibold text-ink">{hover.name}</p>
          <p className="font-mono text-xs text-cyan-300">{compactNumber(hover.count)} indicator IPs</p>
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-2 right-2 flex items-center gap-2 rounded-lg border border-line bg-base/90 px-3 py-2">
        <span className="text-[10px] uppercase tracking-wider text-faint">0</span>
        <div className="h-2 w-28 rounded-full" style={{ background: 'linear-gradient(to right, #155e75, #22d3ee)' }} />
        <span className="text-[10px] uppercase tracking-wider text-faint">{compactNumber(total)}</span>
      </div>
    </div>
  );
}
