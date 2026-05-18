import { createContext, use } from "react";

export const ApiRootContext = createContext<string | undefined>(undefined);

export const useApiRoot = () => {
  const ctx = use(ApiRootContext);
  if (!ctx) throw new Error("ApiRootContext not found");
  return ctx;
};
