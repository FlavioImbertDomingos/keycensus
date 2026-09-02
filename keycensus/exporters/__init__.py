from . import cbom, csv_export, html_report, json_export

FORMATS = {
    "json": (json_export.render, "inventory.json"),
    "cbom": (cbom.render, "cbom.json"),
    "csv": (csv_export.render, "inventory.csv"),
    "html": (html_report.render, "report.html"),
}

__all__ = ["FORMATS", "cbom", "csv_export", "html_report", "json_export"]
