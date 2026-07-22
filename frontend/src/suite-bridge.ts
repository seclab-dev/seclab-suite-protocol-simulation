import {
  createSuiteBridge,
  type SuiteNotificationPayload,
} from "@seclab-dev/suite-sdk";

export const suiteBridge = createSuiteBridge({
  capabilities: ["theme", "locale", "window", "notification"],
  supportedLocales: ["zh-CN", "en-US"],
  defaultLocale: "zh-CN",
});

export function notifyHost(payload: SuiteNotificationPayload) {
  return suiteBridge.notify(payload);
}
