document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("scan-form");
  const fileInput = document.getElementById("scan-file");
  const contextInput = document.getElementById("architecture-context");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    const file = fileInput.files[0];
    if (!file || !/\.(xlsx|xls|csv)$/i.test(file.name)) {
      showError("Please choose a .xlsx, .xls, or .csv file.");
      return;
    }

    setLoading(true);
    try {
      const { blob, filename } = await analyzeScan(file, contextInput.value.trim());

      let headers, rows;
      try {
        const buffer = await blob.arrayBuffer();
        ({ headers, rows } = parseWorkbookToRows(buffer));
      } catch (parseErr) {
        showError(
          "Received a result but could not render it as a table. You can still download it below."
        );
        wireDownloadButton(blob, filename);
        document.getElementById("result-section").classList.remove("hidden");
        return;
      }

      renderResultTable(headers, rows);
      wireDownloadButton(blob, filename);
      document.getElementById("result-section").classList.remove("hidden");
    } catch (err) {
      showError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  });
});
