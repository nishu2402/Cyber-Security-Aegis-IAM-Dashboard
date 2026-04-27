function wireSearch(inputId, tableId) {
  const input = document.getElementById(inputId);
  const table = document.getElementById(tableId);
  if (!input || !table) return;

  input.addEventListener("input", () => {
    const q = input.value.toLowerCase().trim();
    table.querySelectorAll("tbody tr").forEach(row => {
      row.style.display = row.innerText.toLowerCase().includes(q) ? "" : "none";
    });
  });
}

function wireUploadScan(formId, targetId) {
  const form = document.getElementById(formId);
  const target = document.getElementById(targetId);
  if (!form || !target) return;

  form.addEventListener("submit", () => {
    target.classList.add("scanning");
  });
}

function generatePDF(reportId, filename) {
  const el = document.getElementById(reportId);
  if (!el || !window.html2pdf) return;

  const opt = {
    margin: 10,
    filename: filename,
    image: { type: 'jpeg', quality: 0.96 },
    html2canvas: { scale: 2, useCORS: true },
    jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
  };

  window.html2pdf().set(opt).from(el).save();
}

window.AegisHUD = { wireSearch, wireUploadScan, generatePDF };
