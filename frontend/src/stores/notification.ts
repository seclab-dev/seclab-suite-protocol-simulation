import { useI18n } from "vue-i18n";
import { notifyHost } from "@/suite-bridge";

type NotifyType = "success" | "error" | "warning" | "info";

/** 向 SecLab 主控发送统一通知，并在独立运行时降级为本地事件。 */
function emit(type: NotifyType, title: string, message: string) {
  const delivered = notifyHost({ type, title, message });
  if (!delivered) {
    window.dispatchEvent(
      new CustomEvent("seclab-suite-notification", {
        detail: { type, title, message },
      }),
    );
  }
  const method =
    type === "error" ? "error" : type === "warning" ? "warn" : "log";
  console[method](`[${type}] ${message}`);
}

/** 提供协议仿真套件统一的本地化通知入口。 */
export function useNotificationStore() {
  const { t } = useI18n();
  const notify = (type: NotifyType, message: string) =>
    emit(type, t(`notification.title.${type}`), message);

  return {
    success: (message: string) => notify("success", message),
    error: (message: string) => notify("error", message),
    warning: (message: string) => notify("warning", message),
    info: (message: string) => notify("info", message),
  };
}
