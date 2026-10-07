const renderResultTable = (headers, rows) => {
  const theadHtml = `<tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr>`;
  const tbodyHtml = rows
    .map(
      (row) =>
        `<tr>${headers.map((h) => `<td>${escapeHtml(row[h] ?? "")}</td>`).join("")}</tr>`
    )
    .join("");
  document.getElementById("result-table").innerHTML =
    `<thead>${theadHtml}</thead><tbody>${tbodyHtml}</tbody>`;
};

const wireDownloadButton = (blob, filename) => {
  const btn = document.getElementById("download-btn");
  btn.onclick = () => triggerDownload(blob, filename);
  btn.disabled = false;
};
