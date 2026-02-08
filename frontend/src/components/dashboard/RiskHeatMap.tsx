import React from 'react';
import { useNavigate } from 'react-router-dom';
import { RISK_LEVELS, RISK_SOLID, getCategoryLabel } from '../../constants/metrics';

interface CategoryRiskData {
  key: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface RiskHeatMapProps {
  categories: CategoryRiskData[];
}

function getCellIntensity(count: number, maxCount: number): number {
  if (count === 0) return 0;
  if (maxCount === 0) return 0;
  return Math.min(1, count / maxCount);
}

export default function RiskHeatMap({ categories }: RiskHeatMapProps) {
  const navigate = useNavigate();

  // Calculate max count for intensity scaling
  const maxCount = Math.max(
    ...categories.flatMap(c => [c.critical, c.high, c.medium, c.low, c.info]),
    1
  );

  const handleCellClick = (category: string, riskLevel: string) => {
    navigate(`/identities?identity_category=${encodeURIComponent(category)}&risk_level=${encodeURIComponent(riskLevel)}`);
  };

  return (
    <div className="bg-white border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b bg-gray-50">
        <h3 className="text-sm font-semibold text-gray-900">Risk Heat Map</h3>
        <p className="text-xs text-gray-500 mt-1">Click any cell to view filtered identities</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Category</th>
              {RISK_LEVELS.map(level => (
                <th key={level} className="px-3 py-3 text-center text-xs font-medium text-gray-500 uppercase">
                  {level}
                </th>
              ))}
              <th className="px-3 py-3 text-center text-xs font-medium text-gray-500 uppercase">Total</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {categories.map(cat => (
              <tr key={cat.key} className="hover:bg-gray-50">
                <td className="px-4 py-3 text-sm font-medium text-gray-900">
                  {getCategoryLabel(cat.key)}
                </td>
                {RISK_LEVELS.map(level => {
                  const count = cat[level as keyof CategoryRiskData] as number;
                  const intensity = getCellIntensity(count, maxCount);
                  const colors = RISK_SOLID[level];

                  return (
                    <td key={level} className="px-3 py-3 text-center">
                      {count > 0 ? (
                        <button
                          onClick={() => handleCellClick(cat.key, level)}
                          className={`
                            inline-flex items-center justify-center
                            min-w-[40px] px-2 py-1 rounded-lg
                            text-sm font-semibold
                            ${colors.bg} ${colors.hoverBg} ${colors.text}
                            transition cursor-pointer
                          `}
                          style={{ opacity: 0.4 + intensity * 0.6 }}
                        >
                          {count}
                        </button>
                      ) : (
                        <span className="text-gray-300">—</span>
                      )}
                    </td>
                  );
                })}
                <td className="px-3 py-3 text-center">
                  <span className="text-sm font-bold text-gray-900">{cat.total}</span>
                </td>
              </tr>
            ))}
          </tbody>
          <tfoot className="border-t bg-gray-50">
            <tr>
              <td className="px-4 py-3 text-sm font-semibold text-gray-900">Total</td>
              {RISK_LEVELS.map(level => {
                const total = categories.reduce((sum, c) => sum + (c[level as keyof CategoryRiskData] as number), 0);
                const colors = RISK_SOLID[level];
                return (
                  <td key={level} className="px-3 py-3 text-center">
                    <span className={`inline-flex items-center justify-center min-w-[40px] px-2 py-1 rounded-lg text-sm font-bold ${colors.bg} ${colors.text}`}>
                      {total}
                    </span>
                  </td>
                );
              })}
              <td className="px-3 py-3 text-center">
                <span className="text-lg font-bold text-gray-900">
                  {categories.reduce((sum, c) => sum + c.total, 0)}
                </span>
              </td>
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  );
}
