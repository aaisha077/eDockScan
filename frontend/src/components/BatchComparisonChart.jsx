import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function BatchComparisonChart({ results, height = 400 }) {
    const getColor = (verdict) => {
        switch (verdict) {
            case 'SAFE': return '#10b981';
            case 'SUSPICIOUS': return '#f59e0b';
            case 'RISKY': return '#ef4444';
            default: return '#64748b';
        }
    };

    const sortedResults = [...results].sort((a, b) => b.riskScore - a.riskScore);

    const truncateImageName = (name, maxLength = 20) => {
        if (name.length <= maxLength) return name;
        const parts = name.split(':');
        if (parts.length > 1) {
            const [repo, tag] = parts;
            return `${repo.substring(0, maxLength - tag.length - 4)}...:${tag}`;
        }
        return name.substring(0, maxLength) + '...';
    };

    const chartData = sortedResults.map(result => ({
        ...result,
        displayName: truncateImageName(result.image),
    }));

    return (
        <div className="w-full">
            <ResponsiveContainer width="100%" height={height}>
                <BarChart
                    data={chartData}
                    margin={{ top: 20, right: 30, left: 20, bottom: 60 }}
                >
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis
                        dataKey="displayName"
                        angle={-45}
                        textAnchor="end"
                        height={100}
                        tick={{ fill: '#94a3b8', fontSize: 11 }}
                    />
                    <YAxis
                        domain={[0, 100]}
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
                        label={{ value: 'Risk Score', angle: -90, position: 'insideLeft', fill: '#cbd5e1' }}
                    />
                    <Tooltip
                        contentStyle={{
                            backgroundColor: '#1e293b',
                            border: '1px solid #475569',
                            borderRadius: '8px',
                            color: '#e2e8f0',
                        }}
                        formatter={(value) => [`${value}`, 'Risk Score']}
                        labelFormatter={(label) => {
                            const result = chartData.find(r => r.displayName === label);
                            return result ? result.image : label;
                        }}
                    />
                    <Bar dataKey="riskScore" radius={[4, 4, 0, 0]}>
                        {chartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={getColor(entry.verdict)} />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>

            <div className="flex justify-center gap-6 mt-4">
                <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded-sm bg-green-500" />
                    <span className="text-sm text-slate-300">Safe</span>
                </div>
                <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded-sm bg-amber-500" />
                    <span className="text-sm text-slate-300">Suspicious</span>
                </div>
                <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded-sm bg-red-500" />
                    <span className="text-sm text-slate-300">Risky</span>
                </div>
            </div>
        </div>
    );
}