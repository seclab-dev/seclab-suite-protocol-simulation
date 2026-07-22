type NotifyType = "success" | "error" | "warning" | "info";

function emit(type: NotifyType, message: string) {
  window.dispatchEvent(
    new CustomEvent("seclab-suite-notification", { detail: { type, message } }),
  );
  const method =
    type === "error" ? "error" : type === "warning" ? "warn" : "log";
  console[method](`[${type}] ${message}`);
}

export function useNotificationStore() {
  return {
    success: (message: string) => emit("success", message),
    error: (message: string) => emit("error", message),
    warning: (message: string) => emit("warning", message),
    info: (message: string) => emit("info", message),
  };
}
