
import { featureExplanations, getRiskLevelColor } from '../utils/featureExplanations';
import { HelpCircle, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

export default function FeatureTooltip({ feature, value }) {
    const explanation = featureExplanations[feature];

    if (!explanation) {
        return <span className="text-slate-300">{feature.replace(/_/g, ' ')}</span>;
    }

    const colorClass = getRiskLevelColor(feature, value);

    return (
        <div className="group relative inline-flex items-center gap-2">
            <span className="cursor-help underline decoration-dotted decoration-slate-500">
                {explanation.title}
            </span>
            <HelpCircle className="w-4 h-4 text-slate-500" />

            {/* Tooltip */}
            <div className="invisible group-hover:visible absolute z-50 left-0 top-full mt-2 w-96 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl p-4">
                {/* Header */}
                <div className="flex items-start justify-between mb-3">
                    <h4 className="font-bold text-cyan-400 text-lg">{explanation.title}</h4>
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${colorClass} bg-slate-800`}>
                        {value}
                    </span>
                </div>

                {/* Description */}
                <p className="text-sm text-slate-300 mb-3 leading-relaxed">
                    {explanation.description}
                </p>

                {/* Impact */}
                <div className="mb-3 p-2 bg-slate-800 rounded border-l-4 border-orange-500">
                    <div className="flex items-center gap-2 mb-1">
                        <AlertTriangle className="w-4 h-4 text-orange-400" />
                        <span className="text-xs font-semibold text-orange-400">IMPACT</span>
                    </div>
                    <p className="text-xs text-slate-300">{explanation.impact}</p>
                </div>

                {/* Good vs Bad Values */}
                <div className="grid grid-cols-2 gap-2 mb-3">
                    <div className="p-2 bg-green-900/20 border border-green-700 rounded">
                        <div className="flex items-center gap-1 mb-1">
                            <CheckCircle className="w-3 h-3 text-green-400" />
                            <span className="text-xs font-semibold text-green-400">Good</span>
                        </div>
                        <p className="text-xs text-slate-300">{explanation.good}</p>
                    </div>

                    <div className="p-2 bg-red-900/20 border border-red-700 rounded">
                        <div className="flex items-center gap-1 mb-1">
                            <XCircle className="w-3 h-3 text-red-400" />
                            <span className="text-xs font-semibold text-red-400">Bad</span>
                        </div>
                        <p className="text-xs text-slate-300">{explanation.bad}</p>
                    </div>
                </div>

                {/* Fix Suggestion (if exists) */}
                {explanation.fix && (
                    <div className="p-2 bg-cyan-900/20 border border-cyan-700 rounded">
                        <div className="flex items-center gap-1 mb-1">
                            <span className="text-xs font-semibold text-cyan-400">💡 FIX</span>
                        </div>
                        <p className="text-xs text-slate-300">{explanation.fix}</p>
                    </div>
                )}

                {/* Examples (if exists) */}
                {explanation.examples && (
                    <div className="mt-2 p-2 bg-slate-800 rounded">
                        <span className="text-xs font-semibold text-slate-400">Examples: </span>
                        <code className="text-xs text-purple-400">{explanation.examples}</code>
                    </div>
                )}

                {/* Pattern (if exists) */}
                {explanation.pattern && (
                    <div className="mt-2 p-2 bg-slate-800 rounded">
                        <span className="text-xs font-semibold text-slate-400">Pattern: </span>
                        <code className="text-xs text-purple-400 block mt-1">{explanation.pattern}</code>
                    </div>
                )}

                {/* Arrow pointer */}
                <div className="absolute -top-2 left-4 w-4 h-4 bg-slate-900 border-l border-t border-slate-700 transform rotate-45"></div>
            </div>
        </div>
    );
}