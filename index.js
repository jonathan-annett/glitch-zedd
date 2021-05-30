const zedd = require("zedd");

var autoPass = true;

const zeddOptions = {
  root: "/app/public",
  route: "/zedd/",
  TLSKey: "/app/keys.json",
  enableRun: false,
  remote: true
};

zedd.setOptions(zeddOptions);

const ZEDD = zedd();
const secureJSON = require("glitch-secure-json");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function getAutoPass() {
  if (!getAutoPass.cache) {
    const config = secureJSON.parse(fs.readFileSync(zeddOptions.TLSKey));
    let dirty=false;
    autoPass = config.autoPass;
    getAutoPass.cache = true;
    if (typeof autoPass === "object") {
      autoPass = autoPass.refresh;
      config.autoPass = (autoPass = autoPass.refresh);
      dirty=true;
    }
    if (typeof autoPass === "undefined") {
       config.autoPass = (autoPass = true);
      dirty=true;
    }
    if (dirty) {
      fs.writeFileSync(zeddOptions.TLSKey, secureJSON.stringify(config));
    }
  }
  return autoPass;
}

function setAutoPass(value) {
  const config = secureJSON.parse(fs.readFileSync(zeddOptions.TLSKey));
  config.autoPass = autoPass = value;
  fs.writeFileSync(zeddOptions.TLSKey, secureJSON.stringify(config));
}

function newPasswords() {
  const config = {
      domain: process.env.PROJECT_DOMAIN + ".glitch.me",
      aux: require(path.join(
        path.dirname(require.resolve("server-startup")),
        "genpass"
      )).auxPasswords(2),
      key: "",
      cert: ""
    },
    seeds = Buffer.from(
      JSON.stringify([
        config.aux.nonce1,
        config.aux.nonce2,
        config.aux.nonce3,
        config.aux.nonce4
      ])
    );

  config.autoPass = autoPass;
  
  config.aux.pass1 = crypto.createHash("sha256")
    .update(Buffer.concat([seeds, Buffer.from(config.aux.pass1)]))
    .digest("base64")
    .replace(ZEDD.base64FuglyChars, "");
  
  
  const zeddpass = crypto.createHash("sha256")
    .update(Buffer.concat([seeds, Buffer.from(config.aux.pass2)]))
    .digest("base64")
    .replace(ZEDD.base64FuglyChars, "");
 
  config.aux.pass2 = crypto.createHash("sha256")
    .update(Buffer.concat([seeds, Buffer.from(zeddpass)]))
    .digest("base64")
    .replace(ZEDD.base64FuglyChars, "");

  fs.writeFileSync(zeddOptions.TLSKey, secureJSON.stringify(config));

  return {
    url: "https://" + config.domain + zeddOptions.route,
    name: config.aux.pass1,
    pass: zeddpass
  };
}

module.exports = function(rootpath) {
  if (rootpath && require('fs').existsSync(rootpath)&&require('fs').statSync(rootpath).isDirectory()) {
    zeddOptions.root=rootpath.replace(/\/$/,'');
  }
  const ZeddRequest = ZEDD.middleware();

  if (getAutoPass()) console.log("new credentials for Zedd", newPasswords());

  return function ZeddOnGlitchMiddleWare(req, res, next) {
    if (!req.url.startsWith(zeddOptions.route)) {
      return next();
    }

    req.zedd_auth = ZEDD.checkUserPass(require("basic-auth")(req));

    if (!req.zedd_auth) {
      res.writeHead(401, {
        "WWW-Authenticate": 'Basic realm="Zed daemon"'
      });
      return res.end();
    }
    const basepath = path.basename(req.url); 
    console.log(basepath);
    switch (basepath) {
      case "--newpass":
        const newPass = newPasswords();
        console.log("new credentials for Zedd", newPass);
        res.type("text");
        res.setHeader("ETag", Date.now().toString(36).substr(2));
        return res.status(404).send("check Glitch Tools/Logs window");
        
      case  "---refresh":
        res.type("text");
        res.setHeader("ETag", Date.now().toString(36).substr(2));
        res.status(404).send("check Glitch Tools/Logs window");
        console.log("refreshing the glitch browser");
        setAutoPass({refreshing:getAutoPass()});
       
        
       return require('child_process').execFile('/usr/bin/refresh', [], function (error, stdout, stderr) {
            process.exit();

        }); 
       
      case "--auto-off":
        setAutoPass(false);
        res.type("text");
        res.setHeader("ETag", Date.now().toString(36).substr(2));
        console.log("server will not regenerate new password on restart");
        return res.status(404).send("autopass-off");

      case "--auto-on":
        setAutoPass(true);
        res.type("text");
        res.setHeader("ETag", Date.now().toString(36).substr(2));
        console.log("server will regenerate new password on restart");
        return res.status(404).send("autopass-on");

      default:
        return ZeddRequest(req, res, next);
    } 
  };
};

