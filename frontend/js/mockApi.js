const mockAnalyze = async (file, architectureContext) => {
  await new Promise((resolve) => setTimeout(resolve, 1200));

  if (/error/i.test(file.name)) {
    throw new Error("Simulated analysis failure (mock mode).");
  }

  const buffer = await file.arrayBuffer();
  const { headers, rows } = parseWorkbookToRows(buffer);

  const augmentedRows = rows.map((row) => ({
    ...row,
    justification: "Mock justification: risk accepted given current exposure.",
    remediation: "Mock remediation: upgrade to the fixed version listed above.",
  }));

  const sheet = XLSX.utils.json_to_sheet(augmentedRows, {
    header: [...headers, "justification", "remediation"],
  });
  const csv = XLSX.utils.sheet_to_csv(sheet);
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const filename = file.name.replace(/\.[^.]+$/, "") + "-mock-remediated.csv";

  return { blob, filename };
};
