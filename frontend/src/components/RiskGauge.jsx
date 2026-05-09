import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

export default function RiskGauge({ score, size = 280 }) {
    const getColor = (score) => {
        if (score < 30) return '#10b981';
        if (score < 70) return '#f59e0b';
        return '#ef4444';
    };

    const getZoneLabel = (score) => {
        if (score < 30) return 'SAFE';
        if (score < 70) return 'WARNING';
        return 'RISKY';
    };

    const gaugeData = [
        { value: 30, color: '#10b981' },
        { value: 40, color: '#f59e0b' },
        { value: 30, color: '#ef4444' },
        { value: 100, color: '#1e293b' },
    ];

    const needleAngle = 180 - (score * 1.8);

    return (
        <div className="relative flex flex-col items-center" style={{ width: size, height: size * 0.65 }}>
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={gaugeData}
                        cx="50%"
                        cy="85%"
                        startAngle={180}
                        endAngle={0}
                        innerRadius="70%"
                        outerRadius="90%"
                        paddingAngle={0}
                        dataKey="value"
                    >
                        {gaugeData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                        ))}
                    </Pie>
                </PieChart>
            </ResponsiveContainer>

            <div
                className="absolute bottom-[15%] left-1/2 origin-bottom"
                style={{
                    width: '3px',
                    height: size * 0.35,
                    background: 'linear-gradient(to top, #a855f7, #ec4899)',
                    transform: `translateX(-50%) rotate(${needleAngle}deg)`,
                    transition: 'transform 1s ease-out',
                }}
            >
                <div className="absolute -top-2 -left-1.5 w-4 h-4 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full shadow-lg" />
            </div>

            <div className="absolute bottom-[5%] left-1/2 -translate-x-1/2 text-center">
                <div className="text-5xl font-bold bg-gradient-to-br from-purple-400 to-pink-400 bg-clip-text text-transparent">
                    {score}
                </div>
                <div className="text-sm font-semibold mt-1" style={{ color: getColor(score) }}>
                    {getZoneLabel(score)}
                </div>
            </div>
        </div>
    );
}