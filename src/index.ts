import { Request } from "./request";
import { IOptionsHTTP, IOptionsHTTPS, IResult } from "./interface";
import { log } from "./util";
/**
 * NTLM Client to request protected content over http(s)
 */
export class NtlmClient {
  static tough: any;
  static cookie: any;
  static cookieJar: any;

  public async request(
    url: string | IOptionsHTTP | IOptionsHTTPS,
    user: string = "",
    pwd: string = "",
    workstation?: string,
    domain?: string,
    options?: IOptionsHTTP | IOptionsHTTPS
  ): Promise<IResult> {
    log(
      { name: "request" },
      options || { debug: (url as any).debug },
      "init request"
    );
    return Request.request(
      setOptions(url, user, pwd, workstation, domain, options)
    );
  }
}

function setOptions(
  url: string | IOptionsHTTP | IOptionsHTTPS,
  user: string,
  pwd: string,
  workstation?: string,
  domain?: string,
  options?: IOptionsHTTP | IOptionsHTTPS
): IOptionsHTTP | IOptionsHTTPS {
  options = options || {};
  if (typeof url === "string") {
    options.url = url;
  } else {
    options = url;
  }
  options.user = user;
  options.pwd = pwd;
  options.workstation = workstation;
  options.domain = domain;
  options.method = options.method || "GET";
  options.headers = options.headers || {};
  options.requests = 0;
  NtlmClient.tough = options.tough || NtlmClient.tough;
  if (options.tough) {
    log(
      { name: "setOptions" },
      options,
      "tough-cookie detected, using this cookie jar..."
    );
    NtlmClient.cookie = NtlmClient.tough.Cookie;
    NtlmClient.cookieJar = new NtlmClient.tough.CookieJar();
  }
  options.cookie = NtlmClient.cookie;
  options.cookieJar = NtlmClient.cookieJar;
  log({ name: "setOptions" }, options, "options setted!");
  return options;
}
