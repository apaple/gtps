const express = require("express")
const app = express();
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const colors = require("colors");
const ask = require("prompt-sync")();
var readline = require('readline');
const rancolor = require("randomcolor");
const request = require("request");
const os = require("os");
const fs = require('fs');
var pk = fs.readFileSync('./key.pem');
var pc = fs.readFileSync('./cert.pem');
var optss = { key: pk, cert: pc };


                                                                                   
console.log (`
              ╔════════════════════════════════════════════╗
            ╔═╣ ® GTPS LOGS                                ║
            ║I║ ® DDOS LOGS                                ║
            ║H║ ® Anti Flood                               ║
            ║I║ ® Anti Str3sser                            ║
            ║R║ ® IP LIMITER                               ║
            ║O║ ® Limiter, RateLimiter                     ║
            ║P║ ® IP Banned                                ║
            ║S║ ® IP Blocker                               ║
            ╚═╣ ® Rate Limiter                             ║
              ╚═══════╦═════════════════════════════╦══════╝
	      ╔═══════╩═════════════════════════════╩══════╗
	      ╚════════════════════════════════════════════╝`.red )
            
function run() {
run()
}

var https = require('https');
var timeout = 10 * 1000;
const { RateLimiterMemory } = require('rate-limiter-flexible');
const prompt = require("prompt-sync")();
const title = require("console-title");
const ipvps = prompt("Server Ip : ");
console.log("══════════════════════════════════════")
const tcpport = prompt("[1]Server Port [443] : ");
console.log("══════════════════════════════════════")
const udpport = prompt("[2]Server Port Udp [17091] : ");
console.log("══════════════════════════════════════")
const httpcode = prompt("[3]HTTP CODE (default 301) : ");
console.log("══════════════════════════════════════")
const httpstatus = prompt("[4]Custom HTTP ");
console.log("══════════════════════════════════════")
console.clear()
var blacklist = new Map();
var helmet = require('helmet');
var RateLimit = require('express-rate-limit');
var RateLimiter = require('limiter').RateLimiter;

        var limiter = new RateLimiter(150, 'hour');
            limiter.removeTokens(1, function(err, remainingRequests) {
            
            });
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(1, 250);
            
            limiter.removeTokens(1, function() {
            });
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(150, 'hour', true);  
            limiter.removeTokens(1, function(err, remainingRequests) {
            if (remainingRequests < 0) {
            response.writeHead(200, {'Content-Type': 'text/html;charset=UTF-8'});
            response.end('200 Too Many Requests - your IP is being rate limited');
            } 
            });
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(10, 'second');
            
            if (limiter.tryRemoveTokens(5))
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(1, 250);
            
            limiter.getTokensRemaining();
            var BURST_RATE = 1024 * 1024 * 150; 
            var FILL_RATE = 1024 * 1024 * 50; 
            var TokenBucket = require('limiter').TokenBucket;
            var bucket = new TokenBucket(BURST_RATE, FILL_RATE, 'second', null);
            const opts = new RateLimiterMemory({
                windowMs: 15*60*1000, 
                max: 100,
                delayMs: 0, 
                points: 50, // 10 points
                duration: 1 // per second 
            });
            const rateLimiter = new RateLimiterMemory({
                points: 50, // 10 points
                duration: 1 // per second  
      
        });
		
var FastRateLimit = require("fast-ratelimit").FastRateLimit;
var messageLimiter = new FastRateLimit({
  threshold : 20,
  ttl       : 60 
});

const rateLimits = require('rate-limit-promise')
 
let requests = rateLimits(50, 1000) // 1 request per 1000ms = 1 second
Promise.all([requests(), requests(), requests()]).then(() => {
});

var ExpressBrute = require('express-brute');

// stores state locally, don't use this in production
var store = new ExpressBrute.MemoryStore();
var bruteforce = new ExpressBrute(store);

const StreamLimiter = require('stream-limiter')
const { Readable } = require('stream') 
 
const rs = new Readable()
rs.push(Buffer.from([77, 97, 114, 115, 104, 97, 108, 108]))
rs.push(null)
 
const sl = StreamLimiter(7)
 
rs.pipe(sl).pipe(process.stdout)

const rateLimit = require("express-rate-limit");

// Enable if you're behind a reverse proxy (Heroku, Bluemix, AWS ELB or API Gateway, Nginx, etc)
// see https://expressjs.com/en/guide/behind-proxies.html
// app.set('trust proxy')

const socketio = require('socket.io')
const redis = require('redis');
const expresslimit = require('express');
const { RateLimiterRedis } = require('rate-limiter-flexible');
const redisClient = redis.createClient({
  enable_offline_queue: false,
});

const maxWrongAttemptsByIPperDay = 100;
const maxConsecutiveFailsByUsernameAndIP = 10;

const limiterSlowBruteByIP = new RateLimiterRedis({
  redis: redisClient,
  keyPrefix: 'login_fail_ip_per_day',
  points: maxWrongAttemptsByIPperDay,
  duration: 60 * 60 * 24,
  blockDuration: 60 * 60 * 24, // Block for 1 day, if 100 wrong attempts per day
});

const limiterConsecutiveFailsByUsernameAndIP = new RateLimiterRedis({
  redis: redisClient,
  keyPrefix: 'login_fail_consecutive_username_and_ip',
  points: maxConsecutiveFailsByUsernameAndIP,
  duration: 60 * 60 * 24 * 90, // Store number for 90 days since first fail
  blockDuration: 60 * 60 * 24 * 365 * 20, // Block for infinity after consecutive fails
});


const NodeRateLimiter = require('node-rate-limiter');
const nodeRateLimiter = new NodeRateLimiter();

NodeRateLimiter.defaults = {
    rateLimit: 5000,
    expiration: 3600000,
    timeout: 500
};

function RequestRateLimitMiddleware(req, res, next) {
  nodeRateLimiter.get(res.yourUniqIdForCurrentSession, (err, limit) => {
    if (err) {
      return next(err);
    }
 
    // res.set('X-RateLimit-Limit', limit.total);
    // res.set('X-RateLimit-Remaining', limit.remaining);
    // res.set('X-RateLimit-Reset', limit.reset);
 
    if (limit.remaining) {
      return next();
    }
    // res.set('Retry-After', limit.reset);
  });
}
    const server = https.createServer(optss, function(req, res) {
    var ip = ((req.headers['cf-connecting-ip'] && req.headers['cf-connecting-ip'].split(', ').length) ? req.headers['cf-connecting-ip'].split(', ')[0]: req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress).split(/::ffff:/g).filter(i => i).join('');
    var banned = [ip];
    blacklist.set(ip + req.url + Date.now() + timeout);
    if (ip.length > 100) {
      ip.length = [];
      return req.connected.destroy();
  }

  messageLimiter.consume(ip)
  .then(() => {
      banned.forEach(async ip => {
          if (ip === ip) {
            req.connection.destroy();
            await add_address(ip)
            blacklist.set(ip, Date.now() + timeout);
          }
          else {
            res.write("");
          }
        });
      message.send();
  })
  .catch(() => {
      res.destroy();
      process.env.BLACKLIST
      add_address(ip);
      return;
  });

  if (!blacklist.has(ip + req.url)) {
      add_address(ip + req.url)
    } else {
      let not_allowed = blacklist.get(ip + req.url);
      if (Date.now() > not_allowed + timeout) {
          blacklist.delete(ip + req.url);
          
        } else {
          blacklist.set(ip + req.url + Date.now() + timeout);
      }
    }

    banned.forEach(async ip => {
        if (ip == ip) {
            // res.write("");
            blacklist.set(ip, Date.now() + timeout);
            await add_address(ip)
        }
        else {
        }
    });

    if (!blacklist.has(ip + req.url)) {
      add_address(ip + req.url)
    } else {
      let not_allowed = blacklist.get(ip + req.url);
      if (Date.now() > not_allowed + timeout) {
          blacklist.delete(ip + req.url);
          
        } else {
          blacklist.set(ip + req.url + Date.now() + timeout);
      }
    }
var packet = `server|${ipvps}\nport|${udpport}\ntype|1\n#maint|Protected By AkuGTPS HTTP\n\nbeta_server|127.0.0.1\nbeta_port|17091\n\nbeta_type|1\nmeta|defined\nRTENDMARKERBS1001`;
var server = https.createServer(optss, function(req, res) {
let FLOOD_TIME = 10000;
let FLOOD_MAX = 100;
let flood = {
    floods: {},
    lastFloodClear: new Date(),
    protect: (io, socket) => {
        if (Math.abs( new Date() - flood.lastFloodClear) > FLOOD_TIME) {
            flood.floods = {};
            flood.lastFloodClear = new Date();
        }
        flood.floods[socket.id] == undefined ? flood.floods[socket.id] = {} : flood.floods[socket.id];
        flood.floods[socket.id].count == undefined ? flood.floods[socket.id].count = 0 : flood.floods[socket.id].count;
        flood.floods[socket.id].count++;
        if (flood.floods[socket.id].count > FLOOD_MAX) {
            io.sockets.connected[socket.id].disconnect();
            return false;
        }
        return true;
    }
}});
let ipAddress = req.connection.remoteAddress;
ipAddress = ipAddress.split(/::ffff:/g).filter(a => a).join('');
req.connection.remoteAddress || 
req.socket.remoteAddress || 
req.connection.socket.remoteAddress
    if (req.url === "/growtopia/server_data.php" && req.method.toLowerCase() === "post") {
        console.log(`[GTPS LOGS] ${ipAddress}`)
        res.write(packet, function (err) {
            if (err)
                console.log(err);      
                if (req.method === "GET") {
                    rateLimiter.consume(1) // consume 10 point per event
                    res.destroy();
                    req.socket.destroy();
                    req.connection.destroy();
                    process.env.BLACKLIST
                }
            else if (req.method === "HEAD") {
                rateLimiter.consume(1) // consume 10 point per event
                res.destroy();
                req.socket.destroy();
                req.connection.destroy();
                process.env.BLACKLIST
            }
            else if (req.method === "TCP") {
                rateLimiter.consume(1) // consume 10 point per event
                res.destroy();
                req.socket.destroy();
                req.connection.destroy();
                process.env.BLACKLIST
            }
			 else if (req.method === "DATAGRAM") {
                rateLimiter.consume(1) // consume 10 point per event
                res.destroy();
                req.socket.destroy();
                req.connection.destroy();
                process.env.BLACKLIST
			 }
				 else if (req.method === "STREAM") {
                rateLimiter.consume(1) // consume 10 point per event
                res.destroy();
                req.socket.destroy();
                req.connection.destroy();
                process.env.BLACKLIST
            }
           
            else if (req.method === "UDP") {
                rateLimiter.consume(1) // consume 10 point per event
                res.destroy();
                req.socket.destroy();
                req.connection.destroy();
                process.env.BLACKLIST
            }
        });
        res.end();
        res.destroy();
   }
   else
    res.writeHead(httpcode,`${httpstatus}` );
    process.env.BLACKLIST
    res.end();
});
app.use(expresslimit)
server.listen(443, '0.0.0.0');
function add_address(address) {
    blacklist.set(address, Date.now() + 5000);
}
server.on("connection", function (socket) {
  let sct = socket.remoteAddress;
  sct = sct.split(/::ffff:/g).filter(i => i).join("");
  if (!blacklist.has(sct)) {
  add_address(sct); {
      
  }

    }
    else {
        var not_allowed = blacklist.get(sct);
        if (Date.now() > not_allowed) {
            blacklist.delete(sct);
        }
        else
        socket.destroy();
        };
});

server.on("connection", function (socket) {
    socket.setTimeout(10 * 1000);
    socket.setKeepAlive(true, this.keepAliveMsecs);
    socket.unref();
    return true;
});
server.on("listening", function () { return console.log(`HTTP Service Started On Port 443 `.green);
}); 
