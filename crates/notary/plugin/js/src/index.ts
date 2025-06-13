import * as main from "./main";

import { PluginVerifierConfig, VerifierOutput } from "./pdk";

export function config(): number {
  const output = main.configImpl();

  const untypedOutput = PluginVerifierConfig.toJson(output);
  Host.outputString(JSON.stringify(untypedOutput));

  return 0;
}

export function verify(): number {
  const untypedInput = JSON.parse(Host.inputString());
  const input = VerifierOutput.fromJson(untypedInput);

  main.verifyImpl(input);

  return 0;
}
