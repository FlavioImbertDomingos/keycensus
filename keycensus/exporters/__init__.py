from . import cbom, csv_export, html_report, json_export


def render_format(fmt: str, inv, cbom_version: str = cbom.DEFAULT_VERSION) -> str:
    render, _ = FORMATS[fmt]
    return render(inv, cbom_version) if fmt == "cbom" else render(inv)


FORMATS = {
    "json": (json_export.render, "inventory.json"),
    "cbom": (cbom.render, "cbom.json"),
    "csv": (csv_export.render, "inventory.csv"),
    "html": (html_report.render, "report.html"),
}

__all__ = ["FORMATS", "cbom", "csv_export", "html_report", "json_export", "render_format"]
