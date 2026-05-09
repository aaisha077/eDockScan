import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function LayerBarChart({ layers, maxHeight = 400 }) {
    const getColor = (score) => {
        if (score < 30) return '#10b981';
        if (score < 70) return '#f59e0b';
        return '#ef4444';
    };

    const truncateCommand = (cmd, maxLength = 25) => {
        if (cmd.length <= maxLength) return cmd;
        return cmd.substring(0, maxLength) + '...';
    };

    const chartData = layers.map(layer => ({
        ...layer,
        displayCommand: truncateCommand(layer.command),
    }));

    return (
        <div className="w-full" style={{ maxHeight }}>
            <ResponsiveContainer width="100%" height={Math.min(layers.length * 40 + 60, maxHeight)}>
                <BarChart
                    data={chartData}
                    layout="vertical"
                    margin={{ top: 5, right: 30, left: 150, bottom: 5 }}
                >
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis
                        type="number"
                        domain={[0, 100]}
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
                        label={{ value: 'Risk Score', position: 'insideBottom', offset: -5, fill: '#cbd5e1' }}
                    />
                    <YAxis
                        type="category"
                        dataKey="displayCommand"
                        tick={{ fill: '#94a3b8', fontSize: 11 }}
                        width={140}
                    />
                    <Tooltip
                        contentStyle={{
                            backgroundColor: '#1e293b',
                            border: '1px solid #475569',
                            borderRadius: '8px',
                            color: '#e2e8f0',
                        }}
                        formatter={(value, name) => {
                            if (name === 'riskScore') return [`${value.toFixed(1)}`, 'Risk Score'];
                            return [value, name];
                        }}
                        labelFormatter={(label) => {
                            const layer = chartData.find(l => l.displayCommand === label);
                            return layer ? `Layer ${layer.layer}: ${layer.command}` : label;
                        }}
                    />
                    <Bar dataKey="riskScore" radius={[0, 4, 4, 0]}>
                        {chartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={getColor(entry.riskScore)} />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}