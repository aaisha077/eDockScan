import { useState } from 'react';
import { generateRecommendations } from '../utils/recommendationEngine';
import { AlertTriangle, CheckCircle, ChevronDown, ChevronUp, Copy } from 'lucide-react';

export default function RecommendationsPanel({ scanResult }) {
    const [expandedId, setExpandedId] = useState(null);
    const recommendations = generateRecommendations(scanResult);

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
    };

    if (recommendations.length === 0) {
        return (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3">
                    <CheckCircle className="w-6 h-6 text-green-400" />
                    <div>
                        <h3 className="text-lg font-bold text-green-400">Excellent Security Posture</h3>
                        <p className="text-sm text-slate-400 mt-1">No critical recommendations at this time.</p>
                    </div>
                </div>
            </div>
        );
    }

    const getPriorityColor = (priority) => {
        const colors = {
            CRITICAL: 'text-red-400',
            HIGH: 'text-orange-400',
            MEDIUM: 'text-yellow-400',
            LOW: 'text-blue-400'
        };
        return colors[priority] || 'text-slate-400';
    };

    const getPriorityBadge = (priority) => {
        const badges = {
            CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
            HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
            MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
            LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30'
        };
        return badges[priority] || 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    };

    return (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <h4 className="text-xl font-bold flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-cyan-400" />
                    Security Recommendations
                </h4>
                <div className="flex gap-2">
                    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(priority => {
                        const count = recommendations.filter(r => r.priority === priority).length;
                        if (count === 0) return null;
                        return (
                            <span key={priority} className={`px-2 py-1 rounded text-xs font-semibold border ${getPriorityBadge(priority)}`}>
                                {count} {priority}
                            </span>
                        );
                    })}
                </div>
            </div>

            {/* Recommendations List */}
            <div className="space-y-3">
                {recommendations.map((rec) => {
                    const isExpanded = expandedId === rec.id;

                    return (
                        <div
                            key={rec.id}
                            className="border border-slate-600 rounded-lg overflow-hidden bg-slate-900/50"
                        >
                            {/* Header - Always Visible */}
                            <button
                                onClick={() => setExpandedId(isExpanded ? null : rec.id)}
                                className="w-full p-4 flex items-center justify-between hover:bg-slate-800/50 transition-colors"
                            >
                                <div className="flex items-center gap-3">
                                    <span className="text-2xl">{rec.icon}</span>
                                    <div className="text-left">
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getPriorityBadge(rec.priority)}`}>
                                                {rec.priority}
                                            </span>
                                            <span className="text-xs text-slate-500">{rec.category}</span>
                                        </div>
                                        <h5 className="font-semibold text-slate-200">{rec.title}</h5>
                                    </div>
                                </div>
                                {isExpanded ?
                                    <ChevronUp className="w-5 h-5 text-slate-400" /> :
                                    <ChevronDown className="w-5 h-5 text-slate-400" />
                                }
                            </button>

                            {/* Expanded Content */}
                            {isExpanded && (
                                <div className="px-4 pb-4 space-y-3 border-t border-slate-700">
                                    {/* Problem */}
                                    <div className="pt-3">
                                        <p className="text-xs font-semibold text-slate-400 mb-1">PROBLEM</p>
                                        <p className="text-sm text-slate-300">{rec.problem}</p>
                                    </div>

                                    {/* Impact */}
                                    <div>
                                        <p className="text-xs font-semibold text-orange-400 mb-1">IMPACT</p>
                                        <pre className="text-sm text-slate-300 whitespace-pre-wrap font-sans">{rec.impact}</pre>
                                    </div>

                                    {/* Solution */}
                                    <div>
                                        <p className="text-xs font-semibold text-green-400 mb-1">SOLUTION</p>
                                        <p className="text-sm text-slate-300">{rec.solution}</p>
                                    </div>

                                    {/* Actions */}
                                    {rec.actions && rec.actions.length > 0 && (
                                        <div>
                                            <p className="text-xs font-semibold text-cyan-400 mb-2">ACTION STEPS</p>
                                            <div className="space-y-2">
                                                {rec.actions.map((action, idx) => (
                                                    <div key={idx} className="bg-slate-950/50 border border-slate-700 rounded p-3">
                                                        <div className="flex items-start justify-between mb-2">
                                                            <span className="text-sm font-medium text-slate-300">
                                                                {idx + 1}. {action.text}
                                                            </span>
                                                            {action.command && (
                                                                <button
                                                                    onClick={() => copyToClipboard(action.command)}
                                                                    className="p-1 hover:bg-slate-700 rounded transition-colors"
                                                                    title="Copy command"
                                                                >
                                                                    <Copy className="w-3 h-3 text-slate-400" />
                                                                </button>
                                                            )}
                                                        </div>
                                                        {action.command && (
                                                            <pre className="text-xs bg-slate-900 p-2 rounded overflow-x-auto text-green-400 font-mono">
                                                                {action.command}
                                                            </pre>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Dockerfile Example */}
                                    {rec.dockerfile && (
                                        <div>
                                            <div className="flex items-center justify-between mb-2">
                                                <p className="text-xs font-semibold text-purple-400">DOCKERFILE FIX</p>
                                                <button
                                                    onClick={() => copyToClipboard(rec.dockerfile)}
                                                    className="flex items-center gap-1 px-2 py-1 bg-slate-700 hover:bg-slate-600 rounded text-xs transition-colors"
                                                >
                                                    <Copy className="w-3 h-3" />
                                                    Copy
                                                </button>
                                            </div>
                                            <pre className="text-xs bg-slate-950 p-3 rounded overflow-x-auto border border-slate-700 font-mono text-slate-300">
                                                {rec.dockerfile}
                                            </pre>
                                        </div>
                                    )}

                                    {/* References */}
                                    {rec.references && rec.references.length > 0 && (
                                        <div>
                                            <p className="text-xs font-semibold text-slate-400 mb-1">LEARN MORE</p>
                                            <div className="space-y-1">
                                                {rec.references.map((link, idx) => (
                                                    <a
                                                        key={idx}
                                                        href={link}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="block text-xs text-cyan-400 hover:text-cyan-300 transition-colors truncate"
                                                    >
                                                        {link}
                                                    </a>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}