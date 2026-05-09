import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts';

export default function BehavioralRadar({ features, size = 400 }) {
    const chartData = Object.entries(features).map(([key, value]) => ({
        feature: key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        value: Math.min(value * 100, 100),
        fullMark: 100,
    }));

    return (
        <div className="flex flex-col items-center" style={{ width: size, height: size }}>
            <ResponsiveContainer width="100%" height="100%">
                <RadarChart data={chartData}>
                    <PolarGrid stroke="#475569" strokeWidth={0.5} />
                    <PolarAngleAxis
                        dataKey="feature"
                        tick={{ fill: '#94a3b8', fontSize: 10 }}
                        tickLine={false}
                    />
                    <PolarRadiusAxis
                        angle={90}
                        domain={[0, 100]}
                        tick={{ fill: '#64748b', fontSize: 10 }}
                        tickCount={6}
                    />
                    <Radar
                        name="Risk Level"
                        dataKey="value"
                        stroke="#a855f7"
                        fill="#a855f7"
                        fillOpacity={0.3}
                        strokeWidth={2}
                    />
                    <Tooltip
                        contentStyle={{
                            backgroundColor: '#1e293b',
                            border: '1px solid #475569',
                            borderRadius: '8px',
                            color: '#e2e8f0',
                        }}
                        formatter={(value) => `${value.toFixed(1)}%`}
                    />
                </RadarChart>
            </ResponsiveContainer>
        </div>
    );
}