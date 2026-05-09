import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import html2canvas from 'html2canvas';
import { Download } from 'lucide-react';

export default function PDFExport({ report, chartRefs }) {
    const generatePDF = async () => {
        // Validate report data
        if (!report || !report.image) {
            alert('No scan data available to export');
            return;
        }

        try {
            const pdf = new jsPDF('p', 'mm', 'a4');
            const pageWidth = pdf.internal.pageSize.getWidth();
            const pageHeight = pdf.internal.pageSize.getHeight();
            let yPos = 20;

            // Header bar - Dark slate
            pdf.setFillColor(30, 41, 59); // slate-800
            pdf.rect(0, 0, pageWidth, 60, 'F');

            // Accent line - Cyan
            pdf.setFillColor(34, 211, 238); // cyan-400
            pdf.rect(0, 60, pageWidth, 3, 'F');

            // Company/Product Name
            pdf.setFont('helvetica', 'bold');
            pdf.setFontSize(28);
            pdf.setTextColor(255, 255, 255);
            pdf.text('eDockScan', 20, 35);

            pdf.setFont('helvetica', 'normal');
            pdf.setFontSize(11);
            pdf.setTextColor(203, 213, 225); // slate-300
            pdf.text('Docker Security Analysis Platform', 20, 45);

            // Main Title
            pdf.setFont('helvetica', 'bold');
            pdf.setFontSize(32);
            pdf.setTextColor(15, 23, 42); // slate-900
            pdf.text('Security Assessment Report', 20, 85);

            // Divider line
            pdf.setDrawColor(226, 232, 240); // slate-200
            pdf.setLineWidth(0.5);
            pdf.line(20, 92, pageWidth - 20, 92);

            // Image Name
            pdf.setFont('helvetica', 'bold');
            pdf.setFontSize(16);
            pdf.setTextColor(71, 85, 105); // slate-600
            pdf.text('Target Image:', 20, 105);

            pdf.setFont('helvetica', 'normal');
            pdf.setFontSize(14);
            pdf.setTextColor(30, 41, 59); // slate-800
            const imageName = report.image || 'Unknown Image';
            const splitImage = pdf.splitTextToSize(imageName, pageWidth - 40);
            pdf.text(splitImage, 20, 115);

            // Verdict Box
            const verdictY = 135;
            const verdictColors = {
                SAFE: { bg: [220, 252, 231], text: [22, 163, 74], border: [134, 239, 172] }, // green
                SUSPICIOUS: { bg: [254, 243, 199], text: [217, 119, 6], border: [252, 211, 77] }, // amber
                RISKY: { bg: [254, 226, 226], text: [220, 38, 38], border: [252, 165, 165] }, // red
            };
            const verdictStyle = verdictColors[report.verdict] || {
                bg: [241, 245, 249],
                text: [71, 85, 105],
                border: [203, 213, 225]
            };

            // Verdict box background
            pdf.setFillColor(...verdictStyle.bg);
            pdf.roundedRect(20, verdictY, pageWidth - 40, 30, 4, 4, 'F');

            // Verdict box border
            pdf.setDrawColor(...verdictStyle.border);
            pdf.setLineWidth(1);
            pdf.roundedRect(20, verdictY, pageWidth - 40, 30, 4, 4, 'S');

            // Verdict text
            pdf.setFont('helvetica', 'bold');
            pdf.setFontSize(20);
            pdf.setTextColor(...verdictStyle.text);
            pdf.text(`VERDICT: ${report.verdict || 'UNKNOWN'}`, pageWidth / 2, verdictY + 12, { align: 'center' });

            pdf.setFont('helvetica', 'normal');
            pdf.setFontSize(12);
            pdf.text(`Risk Score: ${Math.round((report.risk_score || 0) * 100)}% | Severity: ${report.severity || 'N/A'}`,
                pageWidth / 2, verdictY + 22, { align: 'center' });

            // Metadata Section
            const metaY = 180;
            pdf.setFont('helvetica', 'normal');
            pdf.setFontSize(9);
            pdf.setTextColor(100, 116, 139); // slate-500

            pdf.text(`Scan ID: ${report.scan_id || 'N/A'}`, 20, metaY);
            pdf.text(`Date: ${new Date(report.timestamp || Date.now()).toLocaleString()}`, 20, metaY + 6);
            pdf.text(`Confidence: ${report.confidence || 'N/A'}`, 20, metaY + 12);
            pdf.text(`Status: ${report.scan_status || 'N/A'}`, 20, metaY + 18);

            // Footer with branding
            pdf.setDrawColor(226, 232, 240);
            pdf.line(20, pageHeight - 25, pageWidth - 20, pageHeight - 25);

            pdf.setFont('helvetica', 'normal');
            pdf.setFontSize(8);
            pdf.setTextColor(148, 163, 184); // slate-400
            pdf.text('eDockScan v1.0 - ML-Powered Docker Security Platform', pageWidth / 2, pageHeight - 15, { align: 'center' });
            pdf.text('Confidential Security Assessment', pageWidth / 2, pageHeight - 10, { align: 'center' });


            // ===========================
            // PAGE 3: DETAILED FINDINGS
            // ===========================
            pdf.addPage();
            yPos = 20;

            // Page header
            pdf.setFillColor(248, 250, 252);
            pdf.rect(0, 0, pageWidth, 15, 'F');
            pdf.setFont('helvetica', 'bold');
            pdf.setFontSize(10);
            pdf.setTextColor(71, 85, 105);
            pdf.text('DETAILED ANALYSIS', 20, 10);

            yPos = 30;
            pdf.setFont('helvetica', 'bold');
            pdf.setFontSize(20);
            pdf.setTextColor(0, 0, 0);
            pdf.text('Risk Factor Analysis', 20, yPos);
            yPos += 10;

            pdf.setFont('helvetica', 'normal');
            pdf.setFontSize(9);
            pdf.setTextColor(100, 116, 139);
            pdf.text('Top contributing factors to the overall risk assessment', 20, yPos);
            yPos += 10;

            // Top Risk Factors Table
            const topFactors = report.top_risk_factors || [];

            autoTable(pdf, {
                startY: yPos,
                head: [['#', 'Risk Factor', 'Value', 'Impact']],
                body: topFactors.slice(0, 15).map((factor, idx) => [
                    String(idx + 1),
                    (factor.feature?.replace(/_/g, ' ') || 'Unknown').toUpperCase(),
                    String(factor.value || 0),
                    `${Math.round((factor.importance || 0) * 100)}%`,
                ]),
                styles: {
                    fontSize: 9,
                    cellPadding: 3,
                    lineColor: [226, 232, 240],
                    lineWidth: 0.1
                },
                headStyles: {
                    fillColor: [30, 41, 59],
                    textColor: [255, 255, 255],
                    fontSize: 9,
                    fontStyle: 'bold'
                },
                alternateRowStyles: {
                    fillColor: [248, 250, 252]
                },
                columnStyles: {
                    0: { cellWidth: 10, halign: 'center' },
                    1: { cellWidth: 90 },
                    2: { cellWidth: 30, halign: 'center' },
                    3: { cellWidth: 30, halign: 'center', textColor: [220, 38, 38], fontStyle: 'bold' }
                }
            });

            yPos = pdf.lastAutoTable.finalY + 15;

            // Layer Analysis
            if (report.layer_analyses && report.layer_analyses.length > 0) {
                if (yPos > pageHeight - 60) {
                    pdf.addPage();

                    // Page header for new page
                    pdf.setFillColor(248, 250, 252);
                    pdf.rect(0, 0, pageWidth, 15, 'F');
                    pdf.setFont('helvetica', 'bold');
                    pdf.setFontSize(10);
                    pdf.setTextColor(71, 85, 105);
                    pdf.text('DETAILED ANALYSIS (continued)', 20, 10);

                    yPos = 30;
                }

                pdf.setFont('helvetica', 'bold');
                pdf.setFontSize(16);
                pdf.setTextColor(0, 0, 0);
                pdf.text('Layer-by-Layer Analysis', 20, yPos);
                yPos += 8;

                autoTable(pdf, {
                    startY: yPos,
                    head: [['Layer', 'Command', 'Risk %']],
                    body: report.layer_analyses.slice(0, 20).map((layer, idx) => [
                        String(idx + 1),
                        (layer.command || 'Unknown').substring(0, 70) + ((layer.command || '').length > 70 ? '...' : ''),
                        `${Math.round((layer.risk_score || 0) * 100)}%`,
                    ]),
                    styles: {
                        fontSize: 8,
                        cellPadding: 2,
                        lineColor: [226, 232, 240],
                        lineWidth: 0.1
                    },
                    headStyles: {
                        fillColor: [30, 41, 59],
                        textColor: [255, 255, 255],
                        fontSize: 8,
                        fontStyle: 'bold'
                    },
                    alternateRowStyles: {
                        fillColor: [248, 250, 252]
                    },
                    columnStyles: {
                        0: { cellWidth: 15, halign: 'center' },
                        1: { cellWidth: 145 },
                        2: { cellWidth: 20, halign: 'center' }
                    }
                });

                yPos = pdf.lastAutoTable.finalY + 10;
            }

            // ===========================
            // PAGE 4: RECOMMENDATIONS
            // ===========================
            if (report.remediations && report.remediations.length > 0) {
                pdf.addPage();

                // Page header
                pdf.setFillColor(248, 250, 252);
                pdf.rect(0, 0, pageWidth, 15, 'F');
                pdf.setFont('helvetica', 'bold');
                pdf.setFontSize(10);
                pdf.setTextColor(71, 85, 105);
                pdf.text('REMEDIATION RECOMMENDATIONS', 20, 10);

                yPos = 30;
                pdf.setFont('helvetica', 'bold');
                pdf.setFontSize(20);
                pdf.setTextColor(0, 0, 0);
                pdf.text('Security Recommendations', 20, yPos);
                yPos += 10;

                autoTable(pdf, {
                    startY: yPos,
                    head: [['Priority', 'Issue', 'Recommendation']],
                    body: report.remediations.slice(0, 20).map(rem => [
                        rem.severity || 'MEDIUM',
                        (rem.issue || 'No description').substring(0, 60) + ((rem.issue || '').length > 60 ? '...' : ''),
                        (rem.remediation || 'No recommendation').substring(0, 70) + ((rem.remediation || '').length > 70 ? '...' : ''),
                    ]),
                    styles: {
                        fontSize: 8,
                        cellPadding: 3,
                        lineColor: [226, 232, 240],
                        lineWidth: 0.1
                    },
                    headStyles: {
                        fillColor: [30, 41, 59],
                        textColor: [255, 255, 255],
                        fontSize: 9,
                        fontStyle: 'bold'
                    },
                    alternateRowStyles: {
                        fillColor: [248, 250, 252]
                    },
                    columnStyles: {
                        0: { cellWidth: 25, halign: 'center', fontStyle: 'bold' },
                        1: { cellWidth: 70 },
                        2: { cellWidth: 85 }
                    },
                    didParseCell: function (data) {
                        if (data.column.index === 0 && data.cell.section === 'body') {
                            const severity = data.cell.text[0];
                            if (severity === 'CRITICAL') {
                                data.cell.styles.textColor = [220, 38, 38];
                            } else if (severity === 'HIGH') {
                                data.cell.styles.textColor = [234, 88, 12];
                            } else if (severity === 'MEDIUM') {
                                data.cell.styles.textColor = [217, 119, 6];
                            }
                        }
                    }
                });
            }

           
            const totalPages = pdf.getNumberOfPages();
            for (let i = 1; i <= totalPages; i++) {
                pdf.setPage(i);

                // Footer line
                pdf.setDrawColor(226, 232, 240);
                pdf.setLineWidth(0.5);
                pdf.line(20, pageHeight - 15, pageWidth - 20, pageHeight - 15);

                // Footer text
                pdf.setFontSize(7);
                pdf.setTextColor(148, 163, 184);
                pdf.setFont('helvetica', 'normal');
                pdf.text('eDockScan - Confidential Security Report', 20, pageHeight - 8);
                pdf.text(`Page ${i} of ${totalPages}`, pageWidth - 20, pageHeight - 8, { align: 'right' });
            }

            pdf.save(`SecurityReport_${report.image.replace(/[/:]/g, '_')}_${Date.now()}.pdf`);
        } catch (error) {
            console.error('PDF generation failed:', error);
            alert(`Failed to generate PDF: ${error.message}`);
        }
    };

    return (
        <button
            onClick={generatePDF}
            className="group relative flex items-center gap-2 px-6 py-2.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 hover:border-cyan-500 rounded-lg text-slate-200 font-medium transition-all duration-200 shadow-lg hover:shadow-cyan-500/20"
        >
            <Download className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
            <span>Export PDF Report</span>
            <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-cyan-500/0 via-cyan-500/5 to-cyan-500/0 opacity-0 group-hover:opacity-100 transition-opacity"></div>
        </button>
    );
}