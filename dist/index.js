"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const url = require("url");
const axios = require("axios");
const authHeader = require("auth-header");
// from auth-header, but not exposed
const quote = (str) => `"${str.replace(/"/g, '\\"')}"`;
function takeFirst(value) {
    if (value.constructor === Array)
        return value[0];
    return value;
}
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
            const wwwAuthenticate = resp1.response.headers['www-authenticate'];
            const parsedAuthorization = authHeader.parse(wwwAuthenticate);
            ++this.count;
            const nonceCount = ('00000000' + this.count).slice(-8);
            const cnonce = crypto.randomBytes(24).toString('hex');
            const realm = takeFirst(parsedAuthorization.params['realm']);
            const nonce = takeFirst(parsedAuthorization.params['nonce']);
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
                opaque: parsedAuthorization.params['opaque'],
            };
            const paramsString = Object.entries(params).map(([key, value]) => `${key}=${value && quote(value)}`).join(', ');
            const authorization = `Digest ${paramsString}`;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxpQ0FBaUM7QUFDakMsMkJBQTJCO0FBQzNCLCtCQUErQjtBQUMvQiwwQ0FBMEM7QUFFMUMsb0NBQW9DO0FBQ3BDLE1BQU0sS0FBSyxHQUFHLENBQUMsR0FBVyxFQUFVLEVBQUUsQ0FBQyxJQUFJLEdBQUcsQ0FBQyxPQUFPLENBQUMsSUFBSSxFQUFFLEtBQUssQ0FBQyxHQUFHLENBQUM7QUFpQnZFLFNBQVMsU0FBUyxDQUFDLEtBQXNCO0lBQ3ZDLElBQUksS0FBSyxDQUFDLFdBQVcsS0FBSyxLQUFLO1FBQzdCLE9BQU8sS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2xCLE9BQU8sS0FBZSxDQUFDO0FBQ3pCLENBQUM7QUFFRCxNQUFxQixlQUFlO0lBT2xDLFlBQVksRUFBRSxLQUFLLEVBQUUsU0FBUyxFQUFFLFFBQVEsRUFBRSxRQUFRLEVBQXVCO1FBQ3ZFLElBQUksQ0FBQyxLQUFLLEdBQUcsU0FBUyxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUM7UUFDbkQsSUFBSSxDQUFDLEtBQUssR0FBRyxDQUFDLENBQUM7UUFDZixJQUFJLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQztRQUN6QixJQUFJLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQztJQUMzQixDQUFDO0lBRU0sS0FBSyxDQUFDLE9BQU8sQ0FBQyxJQUE4Qjs7UUFDakQsSUFBSTtZQUNGLE9BQU8sTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQztTQUN2QztRQUFDLE9BQU8sS0FBVSxFQUFFO1lBQ25CLElBQUksS0FBSyxDQUFDLFFBQVEsS0FBSyxTQUFTO21CQUN6QixLQUFLLENBQUMsUUFBUSxDQUFDLE1BQU0sS0FBSyxHQUFHO21CQUM3QixDQUFDLENBQUEs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