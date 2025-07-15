import * as main from "./main";

import { PluginOutput, PluginVerifierConfig, VerifierOutput } from "./pdk";

export function config(): number {
  const output = main.configImpl();

  console.log(`configImpl untyped output: ${JSON.stringify(output)}`);
  const untypedOutput = PluginVerifierConfig.toJson(output);
  Host.outputString(JSON.stringify(untypedOutput));

  return 0;
}

export function verify(): number {
  const untypedInput = JSON.parse(Host.inputString());
  const input = VerifierOutput.fromJson(untypedInput);  

  const output = main.verifyImpl(input);
  console.log(`verifyImpl untyped output: ${JSON.stringify(output)}`);
  Host.outputString(JSON.stringify(output));

  return 0;
}
