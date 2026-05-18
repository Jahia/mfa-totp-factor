/**
 * Converts error arguments from array format to object format for i18next interpolation.
 */
export function convertErrorArgsToInterpolation(error: {
  code: string;
  arguments?: Array<{ name: string; value: string }>;
}): { key: string; interpolation: Record<string, string> } {
  const interpolationData: Record<string, string> = {};
  if (error.arguments) {
    error.arguments.forEach((arg) => {
      interpolationData[arg.name] = arg.value;
    });
  }
  return {
    key: error.code,
    interpolation: interpolationData,
  };
}
