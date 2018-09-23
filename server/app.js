/**
 * @description generate weixin jsSdk signature for different appid.
 * @author Sun Lixiang
 */

let Koa = require('koa');
let Router = require('koa-router');
let bodyParser = require('koa-bodyparser');
let koaRequest = require('koa-http-request');
let sha1 = require('sha1');
let cors = require('koa2-cors');
let send = require('koa-send');

const app = new Koa();
// appid/appsecret key value pair
const wechatAccounts = {
  'appid': 'appsecret'
};
// appid/access_token key value pair
let accessTokens = {};
// appid/isAccessTokenRefreshed key value pair
let accessTokenRefreshed = {};
// appid/jsapi_ticket key value pair
let jsApiTickets = {};

// request body parser, support json, form
app.use(bodyParser());

app.use(koaRequest({
  json: true,
  host: 'https://api.weixin.qq.com'
}));

// cors middleware
app.use(cors({
  origin: function() {
    return '*';
  },
  allowMethods: ['POST'],
  allowHeaders: ['Content-Type'],
}));

app.use(async (ctx, next) => {
  if(ctx.path === '/index.html') {
    await send(ctx, ctx.path, {root: __dirname});
  } else if (ctx.path === '/') {
    await send(ctx, ctx.path, {root: __dirname, index: 'index.html'});
  } else {
    next();
  }
});

/**
 * 获取access_token
 * @param {*} ctx 
 * @param {*} appId 
 */
async function getAccessToken(ctx, appId) {
  if (accessTokens[appId]) {
    return {errcode: 0, access_token: accessTokens[appId]};
  } else {

    async function fetchAccessToken() {
      const appSecret = wechatAccounts[appId];
      let res = await ctx.get(`/cgi-bin/token?grant_type=client_credential&appid=${appId}&secret=${appSecret}`);
      if(!res.errcode) {
        accessTokenRefreshed[appId] = true;
        accessTokens[appId] = res.access_token;
        setTimeout(fetchAccessToken, res.expires_in * 1000);
        return {errcode: 0, access_token: accessTokens[appId]};
      } else {
        return res; // for example {"errcode":40013,"errmsg":"invalid appid"}
      }
    }
    return fetchAccessToken();
  }
}

/**
 * 获得jsapi_ticket
 * @param {*Context} ctx 
 * @param {*String} appId 第三方用户唯一凭证
 */
async function getJsApiTicket(ctx, appId) {
  if(accessTokenRefreshed[appId] === true){

    async function fetchJsApiTicket() {
      let res = await ctx.get(`/cgi-bin/ticket/getticket?access_token=${accessTokens[appId]}&type=jsapi`);
      if(res.errcode === 0) {
        jsApiTickets[appId] = res.ticket;
        accessTokenRefreshed[appId] = false;
        setTimeout(fetchJsApiTicket, res.expires_in * 1000);
        return {errcode: 0, ticket: jsApiTickets[appId]};
      } else {
        return res;
      }
    }
    return fetchJsApiTicket();
  } else {
    return {errcode: 0, ticket: jsApiTickets[appId]};
  }
}

/**
 * JS-SDK权限签名算法
 * @param {*String} appId 第三方用户唯一凭证
 * @param {*String} url 当前网页的URL，不包含#及其后面部分
 */
function getPermissionInfo(appId, url) {
  const nonceStr = Math.random().toString(36).substr(2, 15);
  const timestamp = Date.now();
  const strToSignature = `jsapi_ticket=${jsApiTickets[appId]}&noncestr=${nonceStr}&timestamp=${timestamp}&url=${url}`;
  const signature = sha1(strToSignature);
  return {
    appId,
    timestamp, 
    nonceStr,
    signature
  };
}


const router = new Router();
/**
 * @description 获取JSSDK签名信息
 */
router.post('/getPermission', async (ctx, next) => {
  let {appId, url} = ctx.request.body;
  let access = await getAccessToken(ctx, appId);
  if (access.errcode !== 0) return ctx.body = access; 
  let ticket = await getJsApiTicket(ctx, appId);
  if(ticket.errcode !== 0) return ctx.body = ticket;
  ctx.set('Access-Control-Allow-Origin', ctx.headers['origin']);
  let info = getPermissionInfo(appId, url);
  ctx.body = {
    errcode: 0,
    ...info
  };
});

/**
 * @description 强制刷新accessToken，获取jsSdk签名信息
 */
router.post('/getPermissionWithRefresh', async (ctx, next) => {
  let {appId, url} = ctx.request.body;
  accessTokens[appId] = '';
  let access = await getAccessToken(ctx, appId);
  if (access.errcode !== 0) return ctx.body = access; 
  let ticket = await getJsApiTicket(ctx, appId);
  if(ticket.errcode !== 0) return ctx.body = ticket;
  ctx.body = getPermissionInfo(appId, url);
})

app.use(router.routes()).use(router.allowedMethods());
app.listen(3000);