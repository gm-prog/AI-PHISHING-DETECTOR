export type ApiBaseUrlLevel = "ok" | "warning" | "error";

export interface ApiBaseUrlValidation {
  level: ApiBaseUrlLevel;
  code: string;
  message: string;
}

export declare const PLACEHOLDER_MARKERS: readonly string[];
export declare const RESERVED_TLDS: readonly string[];
export declare const LOOPBACK_HOSTNAMES: readonly string[];
export declare const LEVEL_OK: "ok";
export declare const LEVEL_WARNING: "warning";
export declare const LEVEL_ERROR: "error";

export declare function validateApiBaseUrl(
  rawValue: string | undefined | null,
  options?: { deployment?: boolean },
): ApiBaseUrlValidation;

export declare function isDeploymentBuild(
  env?: Record<string, string | undefined>,
): boolean;

export declare function apiBaseUrlGuard(options?: {
  value?: string | undefined;
  env?: Record<string, string | undefined>;
}): {
  name: string;
  apply: "build";
  buildStart(this: { error: (message: string) => never; warn: (message: string) => void }): void;
};
