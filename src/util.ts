import { IOptionsHTTP, IOptionsHTTPS } from "./interface";

export function log(
  ctx: any,
  options: IOptionsHTTP | IOptionsHTTPS,
  message: any
) {
  if (options.debug) {
    console.log(`ntlm-request: ${ctx?.name}  --  ${message}`);
  }
}
