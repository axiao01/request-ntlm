import http from "http";
import https from "https";
import { IOptionsHTTP, IOptionsHTTPS, IResult } from "./interface";
import {
  createBasicMessage,
  createType1Message,
  createType3Message,
  decodeType2Message,
} from "./ntlm";
import { log } from "./util";

const RECURSIVE_LIMIT = 8;

/**
 * Request client to request protected content over http(s)
 */
export class Request {
  static request(options: IOptionsHTTP | IOptionsHTTPS): Promise<IResult> {
    log(this, options, "request init for url: " + options?.url);
    const getProtocol = (url: string | undefined) =>
      url?.startsWith("https://") ? https : http;
    const protocol = getProtocol(options.url);
    return new Promise((res, rej) => {
      this.get(options, protocol, res, rej);
    });
  }

  private static get(
    options: IOptionsHTTP | IOptionsHTTPS,
    protocol: typeof http | typeof https,
    res: any,
    rej: any
  ) {
    const result: IResult = { body: "", headers: {}, status: 0, options };
    (options.requests as number)++;
    log(
      this,
      options,
      `requesting (${options.requests}/${RECURSIVE_LIMIT}) ${options.url}`
    );
    if ((options.requests as number) > RECURSIVE_LIMIT) {
      rej(`recursive request limit (${RECURSIVE_LIMIT}) excedeed!`);
      return;
    }
    try {
      this.setHeaders(options);
      const req = protocol.request(
        options.url as string,
        options,
        (response) => {
          log(
            this,
            options,
            "response " + response?.statusCode + " from " + options.url
          );
          this.setListeners(response, options, result, res);
          this.setCookie(options, response);
          const authMethods = this.getAuthMethods(result, response, options);
          if (
            result.status === 401 &&
            options.user &&
            options.pwd &&
            authMethods?.indexOf("ntlm") !== -1 &&
            !options.authMethod?.includes("ntlm")
          ) {
            this.executeNTLM1(options, protocol, res, rej);
          } else if (
            result.status === 401 &&
            options.user &&
            options.pwd &&
            authMethods?.indexOf("basic") !== -1 &&
            !options.authMethod?.includes("basic")
          ) {
            this.executeBasic(options, protocol, res, rej);
          } else if (
            result.status > 399 &&
            result.status < 500 &&
            options.user &&
            options.pwd &&
            options.headers?.["Authorization"] &&
            options.authMethod?.includes("ntlm")
          ) {
            this.executeNTLM2(result, options, response, protocol, res, rej);
          } else if (
            result.headers?.["Location"] &&
            result.status > 300 &&
            result.status < 310 &&
            !options.disableRedirect
          ) {
            this.executeRedirect(options, result, protocol, res, rej);
          } else {
            log(this, options, "this request can be resolved");
            result.resolve = true;
          }
        }
      );
      setTimeout(() => {
        req.destroy();
      }, options.timeout ?? 120000);
      
      req.on("error", (err) => {
        log(this, options, "error on request!");
        rej(err);
      });
      if (options.body) {
        if (options.headers) {
          options.headers["content-length"] = options.body.length;
        }
        req.write(options.body);
      }
      req.end();
    } catch (error) {
      log(this, options, "error on try!");
      rej(error);
    }
  }

  private static executeRedirect(
    options: IOptionsHTTP | IOptionsHTTPS,
    result: IResult,
    protocol: typeof http | typeof https,
    res: any,
    rej: any
  ) {
    const getUrl = () => {
      const to = result.headers["Location"] as string;
      if (to.startsWith("http:") || to.startsWith("https:")) {
        return to;
      }
      const url = new URL(options.url as string);
      if (to.startsWith("/")) {
        return url.origin + to;
      }
      const parts = options.url?.split("/");
      const sanitized = parts?.slice(0, parts.length - 1);
      return sanitized?.join("/").concat("/").concat(to);
    };
    log(
      this,
      options,
      result.status +
        " Location/Redirect " +
        options.url +
        " -> " +
        result.headers["Location"]
    );
    if (result.status === 301) {
      log(
        this,
        options,
        "setting request method to GET (301 status code requeriment)"
      );
      options.method = "GET";
    }
    options.url = getUrl();
    this.get(options, protocol, res, rej);
  }

  private static setHeaders(options: IOptionsHTTP | IOptionsHTTPS) {
    options.headers = options.headers || {};
    options.authMethod = options.authMethod || [];
    if (options.cookieJar) {
      options.headers.cookie = options.cookieJar
        .getCookiesSync(options.url)
        .map((c: any) => c.cookieString())
        .join("; ");
    }
    log(
      { name: "setHeaders" },
      options,
      "headers = " + JSON.stringify(options.headers)
    );
  }

  private static executeNTLM2(
    result: IResult,
    options: IOptionsHTTP | IOptionsHTTPS,
    response: http.IncomingMessage,
    protocol: typeof https | typeof http,
    res: any,
    rej: any
  ) {
    options.headers = options.headers || {};
    const t2m = decodeType2Message(result.headers["www-authenticate"]);
    log(this, options, "NTLM Step 2 = " + JSON.stringify(t2m));
    const authHeader = createType3Message(
      t2m,
      options?.user || "",
      options?.pwd || "",
      options?.workstation,
      options?.domain
    );
    options.headers["Authorization"] = authHeader;
    this.deleteCredentials(options);
    response.resume();
    this.get(options, protocol, res, rej);
  }

  private static executeBasic(
    options: IOptionsHTTP | IOptionsHTTPS,
    protocol: typeof https | typeof http,
    res: any,
    rej: any
  ) {
    options.authMethod?.push("basic");
    options.headers = options.headers || {};
    options.headers["Authorization"] = createBasicMessage(
      options?.user || "",
      options?.pwd || ""
    );
    this.deleteCredentials(options);
    this.get(options, protocol, res, rej);
  }

  private static deleteCredentials(options: IOptionsHTTP | IOptionsHTTPS) {
    delete options.user;
    delete options.pwd;
    delete options.workstation;
    delete options.domain;
  }

  private static executeNTLM1(
    options: IOptionsHTTP | IOptionsHTTPS,
    protocol: typeof https | typeof http,
    res: any,
    rej: any
  ) {
    options.headers = options.headers || {};
    options.authMethod?.push("ntlm");
    log(this, options, "NTLM Step 1 (ntlm authenticate method allowed)");
    options.agent =
      options.agent || new protocol.Agent({ keepAlive: true, maxSockets: 1 });
    options.headers["Authorization"] = createType1Message(
      options.workstation,
      options.domain
    );
    log(
      this,
      options,
      "Authorization header = " + options.headers["Authorization"]
    );
    this.get(options, protocol, res, rej);
  }

  private static getAuthMethods(
    result: IResult,
    response: http.IncomingMessage,
    options: IOptionsHTTP | IOptionsHTTPS
  ): Array<string> | undefined {
    result.resolve = false;
    result.status = response.statusCode || 0;
    result.headers = response.headers;
    log(
      this,
      options,
      "www-authenticate header = " + response.headers?.["www-authenticate"]
    );
    return response.headers?.["www-authenticate"]
      ?.split(",")
      .map((i) => i.trim().toLowerCase());
  }

  private static setCookie(
    options: IOptionsHTTP | IOptionsHTTPS,
    response: http.IncomingMessage
  ) {
    if (options.cookieJar && options.cookie) {
      const cookiesHeader = response.headers["set-cookie"] || [];
      cookiesHeader.forEach((cookie: any) => {
        log(this, options, "setCookie");
        options.cookieJar.setCookieSync(
          options.cookie.parse(cookie),
          options.url
        );
      });
    }
  }

  private static setListeners(
    response: http.IncomingMessage,
    options: IOptionsHTTP | IOptionsHTTPS,
    result: IResult,
    res: any
  ) {
    response.on("data", (data) => {
      log(this, options, "data received " + data.length + " bytes chunk");
      result.body += data;
    });
    response.on("end", () => {
      if (result.resolve) {
        log(this, options, "resolve with " + result.status);
        (options.agent as http.Agent | https.Agent)?.destroy();
        delete result.resolve;
        res(result);
      }
    });
    response.on('close', () => {
      if (result.resolve) {
        log(this, options, 'resolve with ' + result.status);
        (options.agent as http.Agent | https.Agent)?.destroy();
        delete result.resolve;
        res(result);
      }
    });
  }
}
