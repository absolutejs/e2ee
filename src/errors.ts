export class E2EEConfigurationError extends Error {
  override readonly name = "E2EEConfigurationError";
}

export class E2EEProviderSelectionError extends Error {
  override readonly name = "E2EEProviderSelectionError";

  constructor(
    message: string,
    readonly rejected: Readonly<Record<string, readonly string[]>>,
  ) {
    super(message);
  }
}
