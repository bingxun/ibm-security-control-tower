const parseWorkbookToRows = (arrayBuffer) => {
  const workbook = XLSX.read(arrayBuffer, { type: "array" });
  const sheet = workbook.Sheets[workbook.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });
  const headers = rows.length
    ? Object.keys(rows[0])
    : (XLSX.utils.sheet_to_json(sheet, { header: 1 })[0] || []);
  return { headers, rows };
};
