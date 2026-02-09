import React from 'react';

interface SparklineProps {
  data: number[];
  color?: string;
  width?: number;
  height?: number;
  filled?: boolean;
  showDot?: boolean;
}

const Sparkline: React.FC<SparklineProps> = ({
  data,
  color = '#3b82f6',
  width = 120,
  height = 32,
  filled = true,
  showDot = true,
}) => {
  if (!data || data.length < 2) {
    return (
      <svg width={width} height={height}>
        <line
          x1={0} y1={height / 2}
          x2={width} y2={height / 2}
          stroke={color}
          strokeWidth={1.5}
          strokeDasharray="4 2"
          opacity={0.3}
        />
      </svg>
    );
  }

  const padding = 2;
  const innerWidth = width - padding * 2;
  const innerHeight = height - padding * 2;

  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;

  const points = data.map((value, index) => {
    const x = padding + (index / (data.length - 1)) * innerWidth;
    const y = padding + innerHeight - ((value - min) / range) * innerHeight;
    return { x, y };
  });

  const polylinePoints = points.map(p => `${p.x},${p.y}`).join(' ');

  const areaPoints = polylinePoints
    + ` ${points[points.length - 1].x},${height - padding}`
    + ` ${points[0].x},${height - padding}`;

  const lastPoint = points[points.length - 1];

  return (
    <svg width={width} height={height} className="overflow-visible">
      {filled && (
        <polygon
          points={areaPoints}
          fill={color}
          opacity={0.1}
        />
      )}
      <polyline
        points={polylinePoints}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {showDot && (
        <circle
          cx={lastPoint.x}
          cy={lastPoint.y}
          r={2.5}
          fill={color}
        />
      )}
    </svg>
  );
};

export default Sparkline;
