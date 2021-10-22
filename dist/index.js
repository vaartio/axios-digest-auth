"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const url = require("url");
const axios = require("axios");
const authHeader = require("auth-header");
// from auth-header, but not exposed
const quote = (str) => `"${str.replace(/"/g, '\\"')}"`;
class AxiosDigestAuth {
    constructor({ axios: axiosInst, password, username }) {
        this.axios = axiosInst ? axiosInst : axios.default;
        this.count = 0;
        this.password = password;
        this.username = username;
    }
    async request(opts) {
        var _a, _b;
        try {
            return await this.axios.request(opts);
        }
        catch (resp1) {
            if (resp1.response === undefined
                || resp1.response.status !== 401
                || !((_a = resp1.response.headers["www-authenticate"]) === null || _a === void 0 ? void 0 : _a.includes('nonce'))) {
                throw resp1;
            }
            // const authDetails = resp1.response.headers['www-authenticate'].split(',').map((v: string) => v.split('='));
            const wwwAuthenticate = resp1.response.headers['www-authenticate'];
            const parsedAuthorization = authHeader.parse(wwwAuthenticate);
            ++this.count;
            const nonceCount = ('00000000' + this.count).slice(-8);
            const cnonce = crypto.randomBytes(24).toString('hex');
            // const realm = authDetails.find((el: any) => el[0].toLowerCase().indexOf("realm") > -1)[1].replace(/"/g, '');
            const realm = parsedAuthorization.params['realm'];
            // const nonce = authDetails.find((el: any) => el[0].toLowerCase().indexOf("nonce") > -1)[1].replace(/"/g, '');
            const nonce = parsedAuthorization.params['nonce'];
            const ha1 = crypto.createHash('md5').update(`${this.username}:${realm}:${this.password}`).digest('hex');
            const path = url.parse(opts.url).pathname;
            const ha2 = crypto.createHash('md5').update(`${(_b = opts.method) !== null && _b !== void 0 ? _b : "GET"}:${path}`).digest('hex');
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
            };
            const paramsString = Object.entries(params).map(([key, value]) => `${key}=${value && quote(value)}`).join(', ');
            const authorization = `Digest ${paramsString}`;
            const authorization2 = `Digest username="${this.username}",realm="${realm}",` +
                `nonce="${nonce}",uri="${path}",qop="auth",algorithm="MD5",` +
                `response="${response}",nc="${nonceCount}",cnonce="${cnonce}"`;
            if (opts.headers) {
                opts.headers["authorization"] = authorization;
            }
            else {
                opts.headers = { authorization };
            }
            return this.axios.request(opts);
        }
    }
}
exports.default = AxiosDigestAuth;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxpQ0FBaUM7QUFDakMsMkJBQTJCO0FBQzNCLCtCQUErQjtBQUMvQiwwQ0FBMEM7QUFFMUMsb0NBQW9DO0FBQ3BDLE1BQU0sS0FBSyxHQUFHLENBQUMsR0FBVyxFQUFVLEVBQUUsQ0FBQyxJQUFJLEdBQUcsQ0FBQyxPQUFPLENBQUMsSUFBSSxFQUFFLEtBQUssQ0FBQyxHQUFHLENBQUM7QUFpQnZFLE1BQXFCLGVBQWU7SUFPbEMsWUFBWSxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUUsUUFBUSxFQUFFLFFBQVEsRUFBdUI7UUFDdkUsSUFBSSxDQUFDLEtBQUssR0FBRyxTQUFTLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQztRQUNuRCxJQUFJLENBQUMsS0FBSyxHQUFHLENBQUMsQ0FBQztRQUNmLElBQUksQ0FBQyxRQUFRLEdBQUcsUUFBUSxDQUFDO1FBQ3pCLElBQUksQ0FBQyxRQUFRLEdBQUcsUUFBUSxDQUFDO0lBQzNCLENBQUM7SUFFTSxLQUFLLENBQUMsT0FBTyxDQUFDLElBQThCOztRQUNqRCxJQUFJO1lBQ0YsT0FBTyxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO1NBQ3ZDO1FBQUMsT0FBTyxLQUFVLEVBQUU7WUFDbkIsSUFBSSxLQUFLLENBQUMsUUFBUSxLQUFLLFNBQVM7bUJBQ3pCLEtBQUssQ0FBQyxRQUFRLENBQUMsTUFBTSxLQUFLLEdBQUc7bUJBQzdCLENBQUMsQ0FBQSxNQUFBLEtBQUssQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLGtCQUFrQixDQUFDLDBDQUFFLFFBQVEsQ0FBQyxPQUFPLENBQUMsQ0FBQSxFQUNuRTtnQkFDQSxNQUFNLEtBQUssQ0FBQzthQUNiO1lBRUQsOEdBQThHO1lBRTlHLE1B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