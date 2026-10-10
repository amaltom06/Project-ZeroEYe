let csrf = "";
let organizationId = "";
export function setSession(token: string, orgId: string) {
  csrf = token;
  organizationId = orgId;
}
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      ...(organizationId ? { "X-Organization-ID": organizationId } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok)
    throw new ApiError(response.status, data.error ?? "Request failed");
  return data as T;
}
export const exportUrl = (path: string) => "/api" + path;
export async function download(path: string, filename: string) {
  const response = await fetch("/api" + path, {
    headers: { "X-Organization-ID": organizationId },
    credentials: "same-origin",
  });
  if (!response.ok) throw new Error("Export failed");
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
