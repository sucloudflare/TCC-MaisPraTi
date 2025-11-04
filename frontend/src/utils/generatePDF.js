import jsPDF from 'jspdf';

export async function generatePDF(jobId, vulns) {
  const pdf = new jsPDF();
  let y = 20;
  pdf.setFontSize(18);
  pdf.text('Relatório de Vulnerabilidades', 105, y, { align: 'center' });
  y += 15;
  pdf.setFontSize(12);
  pdf.text(`Job ID: ${jobId}`, 20, y);
  pdf.text(`Data: ${new Date().toLocaleString()}`, 20, y + 7);

  vulns.forEach((v, i) => {
    if (y > 270) { pdf.addPage(); y = 20; }
    y += 15;
    pdf.setFontSize(14);
    pdf.text(v.vulnerabilityType, 20, y);
    pdf.setFontSize(10);
    pdf.text(`URL: ${v.targetUrl.substring(0, 50)}...`, 20, y + 7);
    pdf.text(`Status: ${v.result}`, 20, y + 14);
  });

  pdf.save(`relatorio_${jobId}.pdf`);
}