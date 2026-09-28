import fs from "node:fs/promises";
import path from "node:path";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const [inputPath, outputPath] = process.argv.slice(2);
if (!inputPath || !outputPath) throw new Error("Usage: build.mjs <excel-input.json> <output.xlsx>");
const input = JSON.parse(await fs.readFile(inputPath, "utf8"));
const workbook = Workbook.create();
const font = "Helvetica";
const chartLine = "#0F5E80";
const chartGrid = "#C9C9C9";
// The chart API accepts CSS pixels; these values export as 12 pt, 11 pt, and 10 pt in Excel.
const chartTitleSize = 16;
const axisTitleSize = 14.6666666667;
const axisLabelSize = 13.3333333333;

function styleSheet(sheet, title, source) {
  sheet.showGridLines = false;
  sheet.getRange("A1:H1").merge();
  sheet.getRange("A1").values = [[title]];
  sheet.getRange("A1").format = { font: { name: font, size: 14, bold: true, color: "#1F2937" } };
  sheet.getRange("A2").values = [[source]];
  sheet.getRange("A2").format = { font: { name: font, size: 10, italic: true, color: "#4B5563" } };
}

function table(sheet, startCell, headers, rows, tableName) {
  const startRow = Number(startCell.match(/\d+/)[0]);
  const startCol = startCell.match(/[A-Z]+/)[0].charCodeAt(0) - 65;
  const range = sheet.getRangeByIndexes(startRow - 1, startCol, rows.length + 1, headers.length);
  range.values = [headers, ...rows];
  const header = sheet.getRangeByIndexes(startRow - 1, startCol, 1, headers.length);
  range.format.font = { name: font, size: 10, color: "#1F2937" };
  range.format.verticalAlignment = "center";
  range.format.borders = { preset: "outside", style: "thin", color: "#D1D5DB" };
  sheet.tables.add(range, true, tableName);
  header.format = { fill: "#1F4E78", font: { name: font, size: 10, bold: true, color: "#FFFFFF" }, horizontalAlignment: "center", verticalAlignment: "center" };
  range.format.autofitColumns();
  return range;
}

function aggregateRows(values) {
  return values.map((value) => [
    value.attributeCount,
    value.targetRevealRatio,
    value.revealedAttributeCount,
    value.effectiveRevealRatio,
    value.measuredRuns,
    value.meanVpPayloadBytes,
    value.meanTimeMs,
    value.p50TimeMs,
    value.p95TimeMs,
  ]);
}

function addLineChart(sheet, categories, values, from, to, title, xTitle, yTitle, xNumberFormatCode, yNumberFormatCode) {
  const chart = sheet.charts.add("line", [categories, values]);
  chart.setPosition(from, to);
  chart.title = title;
  chart.titleTextStyle.typeface = font;
  chart.titleTextStyle.fontSize = chartTitleSize;
  chart.titleTextStyle.bold = true;
  chart.hasLegend = false;
  chart.xAxis = {
    axisType: "textAxis",
    numberFormatCode: xNumberFormatCode,
    numberFormatSourceLinked: false,
    textStyle: { typeface: font, fontSize: axisLabelSize },
    tickLabelDistanceFromAxis: 10,
    title: { text: xTitle, textStyle: { typeface: font, fontSize: axisTitleSize } },
  };
  chart.yAxis = {
    numberFormatCode: yNumberFormatCode,
    numberFormatSourceLinked: false,
    textStyle: { typeface: font, fontSize: axisLabelSize },
    tickLabelDistanceFromAxis: 10,
    title: { text: yTitle, textStyle: { typeface: font, fontSize: axisTitleSize } },
  };
  chart.series.items[0].line = { fill: chartLine, style: "solid", width: 2.5 };
  chart.axes.valueAxis.majorGridlines.format.line = {
    color: chartGrid,
    style: "dashed",
    weight: 0.75,
  };
  chart.axes.categoryAxis.majorGridlines.format.line = {
    color: chartGrid,
    style: "solid",
    weight: 0.75,
  };
  return chart;
}

const method = "50 release-mode runs per condition. attributeCount follows the BBS_SAC2026 paper's variable credentialSubject claims; one additional holder-binding identifier is always hidden and signed. Total BBS+ signed messages = attributeCount + 1.";
const f5 = workbook.worksheets.add("Figure5_Data");
styleSheet(f5, "Figure 5 data: VP verification time vs. Claim count (reveal=0.8)", method);
table(f5, "A4", ["credentialSubject attributes", "Target reveal ratio", "Revealed attributes", "Effective reveal ratio", "Measured runs", "VP payload bytes", "Verification mean ms", "Verification p50 ms", "Verification p95 ms"], aggregateRows(input.figure5), "Figure5Data");
f5.getRange("B5:B10").format.numberFormat = "0.0";
f5.getRange("D5:D10").format.numberFormat = "0.000";
f5.getRange("F5:I10").format.numberFormat = "0.000";
addLineChart(f5, f5.getRange("A5:A10"), f5.getRange("G5:G10"), "K4", "T22", "VP verification time vs. Claim count (reveal=0.8)", "Claim count", "VP verification time (ms)", "0", "0.000");

const f6 = workbook.worksheets.add("Figure6_Data");
styleSheet(f6, "Figure 6 data: Payload vs. Target reveal ratio (claim count=7)", method);
table(f6, "A4", ["credentialSubject attributes", "Target reveal ratio", "Revealed attributes", "Effective reveal ratio", "Measured runs", "VP payload bytes", "Generation mean ms", "Generation p50 ms", "Generation p95 ms"], aggregateRows(input.figure6), "Figure6Data");
f6.getRange("B5:B9").format.numberFormat = "0.0";
f6.getRange("D5:D9").format.numberFormat = "0.000";
f6.getRange("F5:I9").format.numberFormat = "0.000";
addLineChart(f6, f6.getRange("B5:B9"), f6.getRange("F5:F9"), "L4", "T22", "Payload vs. Target reveal ratio (claim count=7)", "Target reveal ratio", "VP payload (bytes)", "0.0", "0");

const f7 = workbook.worksheets.add("Figure7_Data");
styleSheet(f7, "Figure 7 data: Payload vs. Claim count (reveal=0.4)", method);
table(f7, "A4", ["credentialSubject attributes", "Target reveal ratio", "Revealed attributes", "Effective reveal ratio", "Measured runs", "VP payload bytes", "Generation mean ms", "Generation p50 ms", "Generation p95 ms"], aggregateRows(input.figure7), "Figure7Data");
f7.getRange("B5:B10").format.numberFormat = "0.0";
f7.getRange("D5:D10").format.numberFormat = "0.000";
f7.getRange("F5:I10").format.numberFormat = "0.000";
addLineChart(f7, f7.getRange("A5:A10"), f7.getRange("F5:F10"), "L4", "T22", "Payload vs. Claim count (reveal=0.4)", "Claim count", "VP payload (bytes)", "0", "0");

const summary = workbook.worksheets.add("Stage_Summary");
styleSheet(summary, "Benchmark stage summary", `Run ${input.runId}. ${method}`);
const summaryRows = input.summary.stages.flatMap((stage) => stage.results.map((value) => [stage.stage, value.figure, value.attributeCount, value.targetRevealRatio, value.revealedAttributeCount, value.effectiveRevealRatio, value.measuredRuns, value.meanTimeMs, value.p50TimeMs, value.p95TimeMs, value.meanVpPayloadBytes]));
table(summary, "A4", ["Stage", "Figure slice", "credentialSubject attributes", "Target reveal ratio", "Revealed attributes", "Effective reveal ratio", "Measured runs", "Mean time ms", "p50 time ms", "p95 time ms", "VP payload bytes"], summaryRows, "StageSummary");
summary.getRangeByIndexes(4, 3, summaryRows.length, 1).format.numberFormat = "0.0";
summary.getRangeByIndexes(4, 5, summaryRows.length, 1).format.numberFormat = "0.000";
summary.getRangeByIndexes(4, 7, summaryRows.length, 4).format.numberFormat = "0.000";
summary.freezePanes.freezeRows(4);

const raw = workbook.worksheets.add("Timing_Raw");
raw.showGridLines = false;
const rawRows = input.rawSamples.map((sample) => [sample.figure, sample.attributeCount, sample.targetRevealRatio, sample.revealedAttributeCount, sample.effectiveRevealRatio, sample.iteration, sample.stage, sample.wallTimeMs, sample.vpPayloadBytes]);
table(raw, "A1", ["Figure slice", "credentialSubject attributes", "Target reveal ratio", "Revealed attributes", "Effective reveal ratio", "Iteration", "Stage", "Wall time ms", "VP payload bytes"], rawRows, "TimingRaw");
raw.getRangeByIndexes(1, 2, rawRows.length, 1).format.numberFormat = "0.0";
raw.getRangeByIndexes(1, 4, rawRows.length, 1).format.numberFormat = "0.000";
raw.getRangeByIndexes(1, 7, rawRows.length, 2).format.numberFormat = "0.000";
raw.freezePanes.freezeRows(1);

workbook.recalculate();
await fs.mkdir(path.dirname(outputPath), { recursive: true });
const output = await SpreadsheetFile.exportXlsx(workbook);
await output.save(outputPath);

const previewRanges = {
  Figure5_Data: "A1:T22",
  Figure6_Data: "A1:T22",
  Figure7_Data: "A1:T22",
  Stage_Summary: "A1:K35",
  Timing_Raw: "A1:I25",
};
for (const [sheetName, range] of Object.entries(previewRanges)) {
  const preview = await workbook.render({ sheetName, range, scale: 1, format: "png" });
  await fs.writeFile(path.join(path.dirname(outputPath), `${sheetName}.png`), new Uint8Array(await preview.arrayBuffer()));
}
