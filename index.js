const crypto = require("crypto");
const express = require("express");
const fidolib = require("fido2-lib");
const cookieParser = require("cookie-parser");
const tweetnacl = require("tweetnacl");
const db = require("./db");
const fs = require("fs");
const app = express();
let logonSessions = {};
let waChallenges = {};
let spChallenges = [];
let brChallenges = {};
let json = express.json();

function requireLogon(req, res, next) {
    if (!db.tokenDB.has(req.cookies.token)) {
        res.clearCookie("token");
        res.cookie("wantedPage", req.originalUrl, {
            maxAge: 1000 * 60 * 3
        });
        return res.redirect("/login");
    }
    let user = db.tokenDB.get(req.cookies.token);
    let userInfo = db.primaryDB.get(user);
    if (userInfo.disableStatus) {
        res.clearCookie("token");
        res.cookie("wantedPage", req.originalUrl, {
            maxAge: 1000 * 60 * 3
        });
        return res.redirect("/login");
    }
    if (req.cookies.wantedPage) {
        let page = req.cookies.wantedPage;
        res.clearCookie("wantedPage");
        return res.redirect(page);
    }
    req.user = user;
    next();
}

function requireNonServiceLogon(req, res, next) {
    if (!db.tokenDB.has(req.cookies.token)) {
        res.clearCookie("token");
        res.cookie("wantedPage", req.originalUrl, {
            maxAge: 1000 * 60 * 3
        });
        return res.redirect("/login");
    }
    let user = db.tokenDB.get(req.cookies.token);
    let userInfo = db.primaryDB.get(user);
    if (userInfo.disableStatus) {
        res.clearCookie("token");
        res.cookie("wantedPage", req.originalUrl, {
            maxAge: 1000 * 60 * 3
        });
        return res.redirect("/login");
    }
    if (userInfo.token != req.cookies.token) return res.redirect("/login");
    if (req.cookies.wantedPage) {
        let page = req.cookies.wantedPage;
        res.clearCookie("wantedPage");
        return res.redirect(page);
    }
    req.user = user;
    next();
}

let ab2h = (buffer) => Array.from(new Uint8Array(buffer)).map(a => a.toString(16).padStart(2, "0")).join("");
let h2u8 = (hex) => Uint8Array.from(hex.match(/.{1,2}/g), c => parseInt(c, 16));

function requireNoLogon(req, res, next) {
    if (req.cookies.token) return res.redirect("/manage");
    next();
}

function cbrMaker(type) {
    if (type != "body" && type != "query") throw new Error("You're weird");
    let cbr = type == "body" ? "confirmBodyReadable" : "cbr";
    return function(req, res, next) {
        if (!req[type][cbr]) return res.status(400).send("Missing confirm body readable");
        if (!brChallenges.hasOwnProperty(req[type][cbr])) return res.status(401).send("Invalid confirm body readable");
        if (brChallenges[req[type][cbr]] != req.user) return res.status(401).send("Invalid confirm body readable");
        delete brChallenges[req[type][cbr]];
        next();
    }
}

function localizeSendFile(s, req, res) {
    let localeExists = false;
    try {
        localeExists = fs.existsSync(__dirname + "/locale-" + req.acceptsLanguages()[0].match(/[a-z]+/g).join("").slice(0, 2) + "/" + s);
    } catch {}
    if (!localeExists) return res.sendFile(__dirname + "/global/" + s);
    res.sendFile(__dirname + "/locale-" + req.acceptsLanguages()[0].match(/[a-z]+/g).join("").slice(0, 2) + "/" + s);
}

let bodyCBR = cbrMaker("body");
let queryCBR = cbrMaker("query");

app.use(cookieParser());
app.get("/", (req, res) => localizeSendFile("index.html", req, res));
app.get("/authn.js", (req, res) => res.sendFile(__dirname + "/authn.js"));
app.get("/style.css", (req, res) => res.sendFile(__dirname + "/style.css"));
app.get("/deviceLogon", requireNonServiceLogon, (req, res) => localizeSendFile("deviceLogon.html", req, res));
app.get("/serviceLogon", requireNonServiceLogon, (req, res) => localizeSendFile("serviceLogonConfirm.html", req, res));
app.get("/serviceLogonSuccess", (req, res) => localizeSendFile("serviceLogonSuccess.html", req, res));
app.get("/serviceLogonFailed", (req, res) => localizeSendFile("serviceLogonFailed.html", req, res));
app.get("/serviceLogonCancelled", (req, res) => localizeSendFile("serviceLogonCancelled.html", req, res));
app.get("/manage", requireNonServiceLogon, (req, res) => localizeSendFile("manage.html", req, res));
app.get("/login", requireNoLogon, (req, res) => localizeSendFile("login.html", req, res));
app.get("/register", requireNoLogon, (req, res) => localizeSendFile("register.html", req, res));
app.get("/imagination/Imagination.js", (req, res) => res.sendFile(__dirname + "/imagination/Imagination.js"));
app.get("/imagination/gui.js", (req, res) => res.sendFile(__dirname + "/imagination/gui.js"));
app.get("/cbor-web.js", (req, res) => res.sendFile(__dirname + "/node_modules/cbor-web/dist/cbor.js"));
app.get("/base32.js", (req, res) => res.sendFile(__dirname + "/node_modules/base32/dist/base32.js"));
app.get("/tweetnacl.js", (req, res) => res.sendFile(__dirname + "/node_modules/tweetnacl/nacl.js"));
app.get("/secure-helper.js", (req, res) => res.sendFile(__dirname + "/secure-helper.js"));
app.get("/devApp", requireNonServiceLogon, (req, res) => localizeSendFile("devApp.html", req, res));
app.get("/logout", requireLogon, (req, res) => res.clearCookie("token").redirect("/login"));
app.get("/sampleApp.html", (req, res) => res.sendFile(__dirname + "/sampleApp.html"));
app.get("/api/username", requireLogon, (req, res) => res.send(req.user));
app.get("/api/apps", requireNonServiceLogon, function(req, res) {
    let userInfo = db.primaryDB.get(req.user);
    let connectedApps = Object.keys(userInfo.apps);
    let output = {};
    for (let app of connectedApps) {
        let owner = db.appDB.get(app);
        if (!owner) {
            output[app] = {
                name: "Deleted App " + app.length + "_" + app.slice(0, 8),
                disabled: true
            }
        } else {
            output[app] = structuredClone(db.primaryDB.get(owner).ownApps[app]);
            delete output[app].dsq;
        }
        output[app].size = JSON.stringify(userInfo.apps[app]).length;
    }
    res.json(output);
});

app.post("/api/apps/remove", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.app) return res.status(400).send("Missing app ID");
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.apps.hasOwnProperty(req.body.app)) return res.status(404).send("App not found");
    db.tokenDB.remove(userInfo.apps[req.body.app].token);
    delete userInfo.apps[req.body.app];
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
})

app.get("/api/data", requireLogon, function(req, res) {
    if (!req.query.app) return res.status(400).send("Missing app ID");
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.apps.hasOwnProperty(req.query.app)) return res.status(404).send("App not found");
    if (userInfo.apps[req.query.app].token != req.cookies.token) return res.status(401).send("Invalid token");
    let appDev = db.appDB.get(req.query.app);
    if (!appDev) return res.status(404).send("This app doesn't exist anymore");
    appDev = db.primaryDB.get(db.appDB.get(req.query.app));
    if (appDev.disableStatus) return res.status(403).send("The developer's account has been disabled");
    appDev = appDev.ownApps[req.query.app];
    if (appDev.disabled) return res.status(403).send("This application is disabled");
    res.json(userInfo.apps[req.query.app].data);
});

app.post("/api/data", requireLogon, json, function(req, res) {
    if (!req.body.app) return res.status(400).send("Missing app ID");
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.apps.hasOwnProperty(req.body.app)) return res.status(404).send("App not found");
    if (userInfo.apps[req.body.app].token != req.cookies.token) return res.status(401).send("Invalid token");
    let appDev = db.appDB.get(req.body.app);
    if (!appDev) return res.status(404).send("This app doesn't exist anymore");
    appDev = db.primaryDB.get(db.appDB.get(req.body.app));
    if (appDev.disableStatus) return res.status(403).send("The developer's account has been disabled");
    appDev = appDev.ownApps[req.body.app];
    if (appDev.disabled) return res.status(403).send("This application is disabled");
    userInfo.apps[req.body.app].data = req.body.data;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.get("/api/selfRemove", requireLogon, function(req, res) {
    if (!req.query.app) return res.status(400).send("Missing app ID");
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.apps.hasOwnProperty(req.query.app)) return res.status(404).send("App not found");
    if (userInfo.apps[req.query.app].token != req.cookies.token) return res.status(401).send("Invalid token");
    db.tokenDB.remove(userInfo.apps[req.query.app].token);
    delete userInfo.apps[req.query.app];
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.get("/api/devApp", requireNonServiceLogon, function(req, res) {
    let ownApps = db.primaryDB.get(req.user).ownApps;
    for (let app in ownApps) delete ownApps[app].dsq;
    res.json(ownApps);
});

app.post("/api/devApp/new", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.name) return res.status(400).send("Missing app name");
    let id = crypto.randomBytes(64).toString("hex");
    let token = crypto.randomBytes(64).toString("hex");
    let userInfo = db.primaryDB.get(req.user);
    userInfo.ownApps[id] = {
        name: req.body.name,
        dsq: token,
        disabled: false
    };
    db.primaryDB.set(req.user, userInfo);
    db.appDB.set(id, req.user);
    db.tokenDB.set(token, req.user);
    res.send(token);
});

app.post("/api/devApps/toggle", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.id) return res.status(400).send("Missing app id");
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.ownApps.hasOwnProperty(req.body.id)) return res.status(404).send("This app isn't registered for this user.");
    userInfo.ownApps[req.body.id].disabled = !userInfo.ownApps[req.body.id].disabled;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.post("/api/devApps/rotate", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.id) return res.status(400).send("Missing app id");
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.ownApps.hasOwnProperty(req.body.id)) return res.status(404).send("This app isn't registered for this user.");
    let token = crypto.randomBytes(64).toString("hex");
    db.tokenDB.remove(userInfo.ownApps[req.body.id].dsq);
    userInfo.ownApps[req.body.id].dsq = token;
    db.primaryDB.set(req.user, userInfo);
    db.tokenDB.set(token, req.user);
    res.send(token);
});

app.post("/api/devApps/rename", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.name) return res.status(400).send("Missing app name");
    if (!req.body.id) return res.status(400).send("Missing app id");
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.ownApps.hasOwnProperty(req.body.id)) return res.status(404).send("This app isn't registered for this user.");
    userInfo.ownApps[req.body.id].name = req.body.name;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.post("/api/devApps/remove", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.id) return res.status(400).send("Missing app id");
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.ownApps.hasOwnProperty(req.body.id)) return res.status(404).send("This app isn't registered for this user.");
    db.tokenDB.remove(userInfo.ownApps[req.body.id].dsq);
    db.appDB.remove(req.body.id);
    delete userInfo.ownApps[req.body.id];
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.get("/api/passkeys", requireNonServiceLogon, (req, res) => res.send(db.primaryDB.get(req.user).passkeys));
app.post("/api/passkey/remove", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    let id = req.body.id;
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.passkeys.hasOwnProperty(id)) return res.status(404).send("This PADD isn't registered for this user.");
    delete userInfo.passkeys[id];
    db.primaryDB.set(req.user, userInfo);
    db.credDB.remove(id);
    res.send("OK");
});
app.post("/api/passkey/rename", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    let id = req.body.id;
    let userInfo = db.primaryDB.get(req.user);
    if (!userInfo.passkeys.hasOwnProperty(id)) return res.status(404).send("This PADD isn't registered for this user.");
    userInfo.passkeys[id].name = req.body.name;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});
app.post("/api/passkey/add", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.name) return res.status(400).send("Missing PADD name");
    if (!req.body.registration) return res.status(400).send("Missing registration");
    if (!req.body.registration.credentialId) return res.status(400).send("Missing credential ID");
    if (!req.body.registration.publicKey) return res.status(400).send("Missing public key");
    if (db.credDB.has(req.body.registration.credentialId)) return res.status(400).send("This credential ID is already registered.");
    let userInfo = db.primaryDB.get(req.user);
    userInfo.passkeys[req.body.registration.credentialId] = {
        name: req.body.name,
        credentialId: req.body.registration.credentialId,
        publicKey: req.body.registration.publicKey,
        backupEligible: req.body.registration.backupEligible,
        counter: 0
    };
    db.primaryDB.set(req.user, userInfo);
    db.credDB.set(req.body.registration.credentialId, req.user);
    res.send("OK");
});

app.post("/api/changeKeypair", requireNonServiceLogon, json, bodyCBR, function(req, res) {
	if (!req.body.pubkey) return res.status(400).send("Bad request!");
	if (db.pubKeyDB.has(req.body.pubkey)) return res.status(400).send("That public key is already taken! Try another one.");
    let userInfo = db.primaryDB.get(req.user);
    let newToken = crypto.randomBytes(64).toString("hex");
    db.pubKeyDB.remove(userInfo.pubkey);
    db.pubKeyDB.set(req.body.pubkey, req.user);
    userInfo.pubkey = req.body.pubkey;
    db.tokenDB.remove(userInfo.token);
    db.tokenDB.set(newToken, req.user);
    userInfo.token = newToken;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.get("/api/terminatePQA", requireNonServiceLogon, queryCBR, function(req, res) {
    let userInfo = db.primaryDB.get(req.user);
    db.pubKeyDB.remove(userInfo.pubkey);
    delete userInfo.pubkey;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
})

app.post("/api/secretQuackChange", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.secretQuack) return res.status(400).send("Missing secret quack");
    let userInfo = db.primaryDB.get(req.user);
    let newToken = crypto.randomBytes(64).toString("hex");
    db.tokenDB.remove(userInfo.token);
    db.tokenDB.set(newToken, req.user);
    userInfo.token = newToken;
    if (!userInfo.secretQuack) userInfo.secretQuack = {};
    userInfo.secretQuack.salt = crypto.randomBytes(64).toString("hex");
    userInfo.secretQuack.hash = crypto.scryptSync(req.body.secretQuack, Buffer.from(userInfo.secretQuack.salt, "hex"), 64).toString("hex");
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.get("/api/terminateSQ", requireNonServiceLogon, queryCBR, function(req, res) {
    let userInfo = db.primaryDB.get(req.user);
    delete userInfo.secretQuack;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.get("/api/terminateUSQA", requireNonServiceLogon, queryCBR, function(req, res) {
    let userInfo = db.primaryDB.get(req.user);
    delete userInfo.shadowPass;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.get("/api/toggleTSSQ", requireNonServiceLogon, queryCBR, function(req, res) {
    let userInfo = db.primaryDB.get(req.user);
    let tssq = userInfo.tssq ? "disabled" : crypto.randomBytes(10).toString("hex");
    userInfo.tssq = tssq;
    if (tssq == "disabled") delete userInfo.tssq;
    db.primaryDB.set(req.user, userInfo);
    res.send(tssq);
});

app.get("/api/rotateManageToken", requireNonServiceLogon, queryCBR, function(req, res) {
    let newToken = crypto.randomBytes(64).toString("hex");
    let userInfo = db.primaryDB.get(req.user);
    db.tokenDB.remove(userInfo.token);
    db.tokenDB.set(newToken, req.user);
    userInfo.token = newToken;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.get("/api/rotateRecoveryToken", requireNonServiceLogon, queryCBR, function(req, res) {
    let newToken = crypto.randomBytes(512).toString("hex");
    let salt = crypto.randomBytes(64).toString("hex");
    let hash = crypto.scryptSync(newToken, Buffer.from(salt, "hex"), 64).toString("hex");
    let userInfo = db.primaryDB.get(req.user);
    userInfo.recoveryToken = { hash, salt };
    db.primaryDB.set(req.user, userInfo);
    res.send(newToken);
});

app.post("/api/secretQuackRegister", json, function(req, res) {
    if (!req.body.username) return res.status(400).send("Missing username");
    if (!req.body.secretQuack) return res.status(400).send("Missing secret quack");
    if (db.primaryDB.has(req.body.username)) return res.status(400).send("This user already exists");
    let salt = crypto.randomBytes(64).toString("hex");
    let token = crypto.randomBytes(64).toString("hex");
    let hash = crypto.scryptSync(req.body.secretQuack, Buffer.from(salt, "hex"), 64).toString("hex");
    db.primaryDB.set(req.body.username, {
        token: token,
        secretQuack: {
            hash, salt
        },
        passkeys: {},
        apps: {},
        ownApps: {},
        disableStatus: false
    });
    db.tokenDB.set(token, req.body.username);
    res.send("OK");
});

app.post("/api/shadowPassRegister", json, function(req, res) {
    if (!req.body.username) return res.status(400).send("Missing username");
    if (!req.body.pubkey) return res.status(400).send("Missing public key");
    if (db.primaryDB.has(req.body.username)) return res.status(400).send("This user already exists");
    db.primaryDB.set(req.body.username, {
        token: token,
        passkeys: {},
        apps: {},
        ownApps: {},
        disableStatus: false,
        shadowPass: req.body.pubkey
    });
    db.tokenDB.set(token, req.body.username);
    res.send("OK");
});

app.get("/api/shadowPassChallenge", async function(req, res) {
    let challenge = crypto.randomBytes(64).toString("hex");
    spChallenges.push(challenge);
    res.send(challenge);
    setTimeout(function() {
        spChallenges.splice(spChallenges.indexOf(challenge), 1);
    }, 60000);
});

app.get("/api/confirmBodyReadable", requireNonServiceLogon, json, async function(req, res) {
    let challenge = crypto.randomBytes(64).toString("hex");
    brChallenges[challenge] = req.user;
    res.send(challenge);
    setTimeout(function() {
        delete brChallenges[challenge];
    }, 60000);
});

app.post("/api/deleteAccount", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    let userInfo = db.primaryDB.get(req.user);
    for (let ownApp in userInfo.ownApps) {
        db.appDB.remove(ownApp);
        db.tokenDB.remove(userInfo.ownApps[ownApp].dsq);
    }
    for (let cred in userInfo.passkeys) db.credDB.remove(cred);
    db.tokenDB.remove(userInfo.token);
    db.pubKeyDB.remove(userInfo.pubkey);
    db.primaryDB.remove(req.user);
    res.send("OK");
});

app.post("/api/lockAccount", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    let userInfo = db.primaryDB.get(req.user);
    userInfo.disableStatus = true;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.post("/api/shadowPassLogin", json, function(req, res) {
    if (!req.body.username) return res.status(400).send("Missing username");
    if (!req.body.response) return res.status(400).send("Missing response");
    if (!req.body.challenge) return res.status(400).send("Missing challenge");
    if (!spChallenges.includes(req.body.challenge)) return res.status(401).send("Invalid challenge");
    spChallenges.splice(spChallenges.indexOf(req.body.challenge), 1);
    if (!db.primaryDB.has(req.body.username)) return res.status(404).send("This user does not exist");
    let user = db.primaryDB.get(req.body.username);
    if (!user.shadowPass) return res.status(400).send("This user does not have USQA set up");
    if (user.disableStatus) return res.status(403).send("This user is disabled");
    
    try {
        if (!tweetnacl.sign.detached.verify(Buffer.from(req.body.challenge, "hex"), Buffer.from(req.body.response, "hex"), Buffer.from(user.shadowPass, "hex")))
            return res.status(400).send("Invalid response");
    } catch {
        return res.status(400).send("Invalid response");
    }

    if (user.tssq) {
        let userTSSQ = user.tssq;
        let totpSecret = Buffer.from("0".repeat(20 - userTSSQ.length) + userTSSQ, "hex");
        let counter = Buffer.from(Math.floor(Date.now() / 30 / 1000).toString(16).padStart(16, "0"), "hex");
        let hmacSign = Array.from(new Uint8Array(crypto.createHmac("sha1", totpSecret).update(Buffer.from(counter)).digest()));
        let offset = hmacSign[19] & 0xf; // https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
        let code = (hmacSign[offset] & 0x7f) << 24
            | (hmacSign[offset + 1] & 0xff) << 16
            | (hmacSign[offset + 2] & 0xff) << 8
            | (hmacSign[offset + 3] & 0xff);
        code = code % 1000000;
        if (code.toString() != req.body.tssq && code.toString().padStart(6, "0") != req.body.tssq) return res.status(401).send("Invalid TSSQ"); 
    }
    res.send(user.token);
});

app.post("/api/shadowPassChange", requireNonServiceLogon, json, bodyCBR, function(req, res) {
    if (!req.body.pubkey) return res.status(400).send("Missing public key");
    let userInfo = db.primaryDB.get(req.user);
    let newToken = crypto.randomBytes(64).toString("hex");
    db.tokenDB.remove(userInfo.token);
    db.tokenDB.set(newToken, req.user);
    userInfo.token = newToken;
    userInfo.shadowPass = req.body.pubkey;
    db.primaryDB.set(req.user, userInfo);
    res.send("OK");
});

app.post("/api/secretQuackLogin", json, function(req, res) {
    if (!req.body.username) return res.status(400).send("Missing username");
    if (!req.body.secretQuack) return res.status(400).send("Missing secret quack");
    if (!db.primaryDB.has(req.body.username)) return res.status(404).send("This user does not exist");
    let user = db.primaryDB.get(req.body.username);
    if (!user.secretQuack) return res.status(400).send("This user does not have a secret quack set");
    let compare = crypto.scryptSync(req.body.secretQuack, Buffer.from(user.secretQuack.salt, "hex"), 64);
    if (compare.toString("hex") != user.secretQuack.hash) return res.status(401).send("Invalid secret quack");
    if (user.disableStatus) return res.status(403).send("This user is disabled");

    if (user.tssq) {
        let userTSSQ = user.tssq;
        let totpSecret = Buffer.from("0".repeat(20 - userTSSQ.length) + userTSSQ, "hex");
        let counter = Buffer.from(Math.floor(Date.now() / 30 / 1000).toString(16).padStart(16, "0"), "hex");
        let hmacSign = Array.from(new Uint8Array(crypto.createHmac("sha1", totpSecret).update(Buffer.from(counter)).digest()));
        let offset = hmacSign[19] & 0xf; // https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
        let code = (hmacSign[offset] & 0x7f) << 24
            | (hmacSign[offset + 1] & 0xff) << 16
            | (hmacSign[offset + 2] & 0xff) << 8
            | (hmacSign[offset + 3] & 0xff);
        code = code % 1000000;
        if (code.toString() != req.body.tssq && code.toString().padStart(6, "0") != req.body.tssq) return res.status(401).send("Invalid TSSQ"); 
    }
    res.send(user.token);
});

app.post("/api/passkeysRegistration", json, function(req, res) {
    if (!req.body.username) return res.status(400).send("Missing username");
    if (!req.body.registration) return res.status(400).send("Missing registration");
    if (!req.body.registration.credentialId) return res.status(400).send("Missing credential ID");
    if (!req.body.registration.publicKey) return res.status(400).send("Missing public key");

    let token = crypto.randomBytes(64).toString("hex");
    if (db.primaryDB.has(req.body.username)) return res.status(400).send("User already exists");
    if (db.credDB.has(req.body.registration.credentialId)) return res.status(400).send("Credential ID already exists");
    db.primaryDB.set(req.body.username, {
        passkeys: {
            [req.body.registration.credentialId]: {
                credentialId: req.body.registration.credentialId,
                publicKey: req.body.registration.publicKey,
                backupEligible: req.body.registration.backupEligible,
                name: "Default Passkey",
                counter: 0
            }
        },
        disableStatus: false,
        apps: {},
        ownApps: {},
        token
    });
    db.credDB.set(req.body.registration.credentialId, req.body.username);
    db.tokenDB.set(token, req.body.username);
    res.send("OK");
});

app.get("/api/passkeysChallenge", async function(req, res) {
    let fl = new fidolib.Fido2Lib();
    let assertionOptions = await fl.assertionOptions();
    assertionOptions.challenge = ab2h(assertionOptions.challenge);
    waChallenges[assertionOptions.challenge] = fl;
    setTimeout(function() {
        delete waChallenges[assertionOptions.challenge];
    }, 60000);
    res.send(assertionOptions.challenge);
});

app.post("/api/passkeysResponse", json, async function(req, res) {
    if (!req.body.challenge) return res.status(400).send("Challenge hex-code is required.");
    if (!req.body.credentialId) return res.status(400).send("Response is required.");
    if (!req.body.credentialIdB) return res.status(400).send("Response is required.");
    if (!req.body.origin) return res.status(400).send("Response is required.");
    if (!req.body.clientDataJSON) return res.status(400).send("Response is required.");
    if (!req.body.signature) return res.status(400).send("Response is required.");
    if (!req.body.authenticatorData) return res.status(400).send("Response is required.");
    if (!waChallenges.hasOwnProperty(req.body.challenge)) return res.status(401).send("Invalid challenge.");
    let user = db.credDB.get(req.body.credentialId);
    if (!user) return res.status(401).send("Wrong credential provided.");
    let registration = db.primaryDB.get(user);
    if (registration.disableStatus) return res.status(403).send("User is disabled.");
    let publicKey = registration.passkeys[req.body.credentialId];
    try {
        let assert = await waChallenges[req.body.challenge].assertionResult({
            rawId: h2u8(req.body.credentialId).buffer,
            id: req.body.credentialIdB,
            type: "public-key",
            response: {
                clientDataJSON: h2u8(req.body.clientDataJSON).buffer,
                signature: h2u8(req.body.signature).buffer,
                authenticatorData: h2u8(req.body.authenticatorData).buffer,
                userHandle: req.body.userHandle ? h2u8(req.body.userHandle).buffer : null,
            }
        }, {
            factor: "either",
            origin: req.body.origin,
            challenge: h2u8(req.body.challenge).buffer,
            prevCounter: publicKey.counter,
            publicKey: (await (await new fidolib.PublicKey().fromCose(h2u8(publicKey.publicKey))).toPem()).toString(),
            userHandle: req.body.userHandle ? h2u8(req.body.userHandle).buffer : null
        });
        if (!assert.audit.complete) return res.status(400).send("Wrong req.body.");
        publicKey.counter = assert.authnrData.get("counter");
        registration.passkeys[req.body.credentialId] = publicKey;
        db.primaryDB.set(user, registration);
        res.send(registration.token);
    } catch {
        res.status(500).send("Something vented wrong.");
    }
    delete waChallenges[req.body.challenge];
});

app.post("/imagination/register", json, function(req, res) {
	if (!req.body.pubkey) return res.status(400).send("Bad request!");
	if (!req.body.username) return res.status(400).send("Bad request!");

	if (db.primaryDB.has(req.body.username)) return res.status(400).send("That user already exists! Try another one.");
	if (db.pubKeyDB.has(req.body.pubkey)) return res.status(400).send("That public key is already taken! Try another one.");
	try {
        let token = crypto.randomBytes(64).toString("hex");
		db.primaryDB.set(req.body.username, {
			pubkey: req.body.pubkey,
            passkeys: {},
            disableStatus: false,
            apps: {},
            ownApps: {},
            token
		});
        db.tokenDB.set(token, req.body.username);
        db.pubKeyDB.set(req.body.pubkey, req.body.username);
	} catch (e) {
		return res.status(500).send("Something went terribly wrong when creating your account");
	}
	res.send("OK");
});

app.get("/imagination/getEncryptedSecret", function(req, res) {
	if (!db.pubKeyDB.has(req.query.pubkey)) return res.status(401).send("Invalid public key: unregistered or blocked user?");
	try {
        let user = db.primaryDB.get(db.pubKeyDB.get(req.query.pubkey));
        if (user.disableStatus) return res.status(403).send("This user is disabled");
		res.send(crypto.publicEncrypt({
			key: req.query.pubkey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		}, Buffer.from(user.token, "utf-8")).toString("base64"));
	} catch (e) {
        console.error(e);
		res.status(500).send("Something went terribly wrong when encrypting the secret token");
	}
});

app.post("/api/serviceLogon/action", requireNonServiceLogon, json, function(req, res) {
    if (!req.body.deviceCode) return res.status(400).send("Device code missing");
    if (!req.body.action) return res.status(400).send("Action missing");
    if (!logonSessions.hasOwnProperty("pub" + req.body.deviceCode)) return res.status(404).send("Invalid device code");
    let session = logonSessions["pub" + req.body.deviceCode];
    let privateSession = logonSessions["pri" + session.forSecure];
    if (privateSession.finished) return res.status(400).send("The session is a zombie");
    if (req.body.action == "deny") {
        privateSession.finished = true;
    } else if (req.body.action == "allow") {
        let userInfo = db.primaryDB.get(req.user);
        let newAppToken = crypto.randomBytes(64).toString("hex");
        privateSession.logonInfo = { user: req.user, appToken: newAppToken };
        if (!userInfo.apps.hasOwnProperty(session.application.id)) userInfo.apps[session.application.id] = { data: {} };
        if (userInfo.apps[session.application.id].token) db.tokenDB.remove(userInfo.apps[session.application.id].token);
        userInfo.apps[session.application.id].token = newAppToken;
        db.primaryDB.set(req.user, userInfo);
        db.tokenDB.set(newAppToken, req.user);
        privateSession.finished = true;
    } else {
        return res.status(400).send("Invalid action");
    }
    res.send("ok");
})

app.post("/api/serviceLogonSession", json, function(req, res) {
    if (!req.body.app) return res.status(400).send("App ID missing");
    if (!req.body.dsq) return res.status(401).send("DSQ missing");
    let token = db.tokenDB.get(req.body.dsq);
    if (!token) return res.status(401).send("Invalid DSQ");
    let user = db.primaryDB.get(token);
    if (user.disableStatus) return res.status(403).send("The developer's account has been disabled");
    if (!user.ownApps.hasOwnProperty(req.body.app)) return res.status(403).send("No such app for this account");
    if (user.ownApps[req.body.app].dsq != req.body.dsq) return res.status(403).send("Invalid DSQ");
    if (user.ownApps[req.body.app].disabled) return res.status(403).send("This application is disabled");
    let deviceCode = crypto.randomBytes(16).toString("hex");
    let deviceReadingCode = crypto.randomBytes(64).toString("hex");
    logonSessions["pub" + deviceCode] = {
        application: { id: req.body.app, name: user.ownApps[req.body.app].name, dev: token },
        ip: req.headers["cf-connecting-ip"] || req.ip,
        redirectURL: req.body.redirectURL || (req.protocol + "://" + req.get("host") + "/serviceLogonSuccess"),
        forSecure: deviceReadingCode
    };
    logonSessions["pri" + deviceReadingCode] = {
        for: deviceCode,
        finished: false,
        logonInfo: {}
    };
    res.json({
        public: deviceCode,
        private: deviceReadingCode
    })
});

app.post("/api/serviceLogonGet", json, function(req, res) {
    if (!req.body.deviceCode) return res.status(400).send("Device code missing");
    if (!logonSessions.hasOwnProperty(req.body.deviceCode)) return res.status(401).send("Invalid device code");
    let result = structuredClone(logonSessions[req.body.deviceCode]);
    delete result.forSecure;
    if (result.finished) {
        delete logonSessions["pub" + result.for];
        delete logonSessions[req.body.deviceCode];
    }
    res.json(result);
});

app.use(function(req, res) { // Point of 404 (no pages past this point)
    res.status(404);
    if (req.headers.accept && req.headers.accept.includes("text/html")) return localizeSendFile("404.html", req, res);
    res.json(404);
})

app.use(function(err, req, res, next) {
    res.status(500).send("Something vent wrong.");
});

app.listen(3942, () => console.log("Listening on port 3942"));