import * as crypto from "crypto";
import * as url from "url";
import * as axios from "axios";
import * as authHeader from 'auth-header';

// from auth-header, but not exposed
const quote = (str: string): string => `"${str.replace(/"/g, '\\"')}"`;

/**
 * Options to configure the AxiosDigestAuth instance.
 */
export interface AxiosDigestAuthOpts {
  /** 
   * optionally provide your own axios instance. if this is not provided, one will be created for 
   * you with default settings.
   */
  axios?: axios.AxiosInstance;
  /** the http digest auth password */
  password: string;
  /** the http digest auth username */
  username: string;
}

function takeFirst(value: string|string[]): string {
  if (value.constructor === Array)
    return value[0];
  return value as string;
}

export default class AxiosDigestAuth {

  private readonly axios: axios.AxiosInstance;
  private count: number;
  private readonly password: string;
  private readonly username: string;

  constructor({ axios: axiosInst, password, username }: AxiosDigestAuthOpts) {
    this.axios = axiosInst ? axiosInst : axios.default;
    this.count = 0;
    this.password = password;
    this.username = username;
  }

  public async request(opts: axios.AxiosRequestConfig): Promise<axios.AxiosResponse> {
    try {
      return await this.axios.request(opts);
    } catch (resp1: any) {
      if (resp1.response === undefined
          || resp1.response.status !== 401
          || !resp1.response.headers["www-authenticate"]?.includes('nonce')
      ) {
        throw resp1;
      }

      const wwwAuthenticate = resp1.response.headers['www-authenticate'];
      const parsedAuthorization = authHeader.parse(wwwAuthenticate);
      ++this.count;
      const nonceCount = ('00000000' + this.count).slice(-8);
      const cnonce = crypto.randomBytes(24).toString('hex');
      const realm = takeFirst(parsedAuthorization.params['realm']);
      const nonce = takeFirst(parsedAuthorization.params['nonce']);

      const ha1 = crypto.createHash('md5').update(`${this.username}:${realm}:${this.password}`).digest('hex');
      const path = url.parse(opts.url!).pathname;
      const ha2 = crypto.createHash('md5').update(`${opts.method ?? "GET"}:${path}`).digest('hex');
      const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nonceCount}:${cnonce}:auth:${ha2}`).digest('hex');

      const params = {
        username: this.username,
        realm,
        nonce,
        uri: path || '',
        qop: 'auth',
        algorithm: 'MD5',
        response,
        nc: nonceCount,
        cnonce,
        opaque: parsedAuthorization.params['opaque'] as string,
      };

      const paramsString = Object.entries(params).map(([key, value]) =>  `${key}=${value && quote(value)}`).join(', ');
      const authorization = `Digest ${paramsString}`;

      if (opts.headers) {
        opts.headers["authorization"] = authorization;
      } else {
        opts.headers = { authorization };
      }
      return this.axios.request(opts);
    }
  }

}
