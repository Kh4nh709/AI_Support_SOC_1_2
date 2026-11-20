import { scenario } from "./data";
export const useLiveStatus = () => (scenario === "offline" ? "offline" : "live");
