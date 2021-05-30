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
    try {
      autoPass = secureJSON.parse(fs.readFileSync(zeddOptions.TLSKey)).autoPass;
      
    } catch (e) {
      autoPass = true;
    }
    
    getAutoPass.cache = true;
    if (typeof autoPass === "undefined") {
      autoPass = true;
    }
  }
  return autoPass;
}

function setAutoPass(value) {
  let config;
  try {
    config = secureJSON.parse(fs.readFileSync(zeddOptions.TLSKey));
    config.autoPass = autoPass = value;
    fs.writeFileSync(zeddOptions.TLSKey, secureJSON.stringify(config));
  } catch (e) {
  }
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

module.exports = function() {
  const ZeddRequest = ZEDD.middleware();

  if (getAutoPass()) console.log("new credentials for Zedd", newPasswords());

  return function ZeddOnGlitchMiddleWare(req, res, next) {
    
    if (!req.url.startsWith(zeddOptions.route)) {
      return next();
    }

    ZEDD.authenticate(req,res,function(){
        // doesnt call here unless authenticated
        console.log("zedd:",req.method,req.url);
        switch (req.url.trim()) {
          case  "--newpass":
            const newPass = newPasswords();
            console.log("new credentials for Zedd", newPass);
            res.type("text");
            res.setHeader("ETag", Date.now().toString(36).substr(2));
            return res.status(404).send("check Glitch Tools/Logs window");

          case  "--auto-off":
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
      
    });
    

  };
};

