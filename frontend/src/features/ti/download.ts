// Hands a file to the browser: an object URL on a blob the page fetched itself (with the Bearer header, through the API client), an
// anchor made for the click and removed at once. The file name is the page's own, chosen by the FORMAT from a closed table; it is never
// read from the answer's headers, the filters or any IOC. The object URL is released a little later (a browser that starts the download
// asynchronously still needs it for a moment).
import { TI_EXPORT_FILES, type TiExportFormat } from "../../api/ti";

const REVOKE_AFTER_MS = 30_000;

/** The name the file is saved under, for a format. */
export const fileNameOf = (format: TiExportFormat): string => TI_EXPORT_FILES[format];

export function saveBlob(blob: Blob, format: TiExportFormat): string {
  const name = fileNameOf(format);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.rel = "noopener";
  link.hidden = true;
  document.body.append(link);
  try {
    link.click();
  } finally {
    link.remove();
  }
  setTimeout(() => URL.revokeObjectURL(url), REVOKE_AFTER_MS);
  return name;
}
