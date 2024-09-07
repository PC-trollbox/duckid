const fs = require("fs");

let cache = JSON.parse(fs.readFileSync(__dirname + "/UserDB.json").toString());
let fullDB = {
    primaryDB: {
        get: function(username) {
            return structuredClone(fullDB._db.primary[username]);
        },
        set: function(username, value) {
            let snapshot = fullDB._db;
            snapshot.primary[username] = value;
            fullDB._db = snapshot;
        },
        remove: function(username) {
            let snapshot = fullDB._db;
            delete snapshot.primary[username];
            fullDB._db = snapshot;
        },
        has: (username) => fullDB._db.primary.hasOwnProperty(username),
        enumerate: () => Object.keys(fullDB._db.primary)
    },
    tokenDB: {
        get: function(token) {
            return structuredClone(fullDB._db.tokens[token]);
        },
        set: function(token, value) {
            let snapshot = fullDB._db;
            snapshot.tokens[token] = value;
            fullDB._db = snapshot;
        },
        remove: function(token) {
            let snapshot = fullDB._db;
            delete snapshot.tokens[token];
            fullDB._db = snapshot;
        },
        has: (token) => fullDB._db.tokens.hasOwnProperty(token),
        enumerate: () => Object.keys(fullDB._db.tokens)
    },
    credDB: {
        get: function(credentialId) {
            return structuredClone(fullDB._db.credentials[credentialId]);
        },
        set: function(credentialId, value) {
            let snapshot = fullDB._db;
            snapshot.credentials[credentialId] = value;
            fullDB._db = snapshot;
        },
        remove: function(credentialId) {
            let snapshot = fullDB._db;
            delete snapshot.credentials[credentialId];
            fullDB._db = snapshot;
        },
        has: (credentialId) => fullDB._db.credentials.hasOwnProperty(credentialId),
        enumerate: () => Object.keys(fullDB._db.credentials)
    },
    pubKeyDB: {
        get: function(pubkey) {
            return structuredClone(fullDB._db.pubkeys[pubkey]);
        },
        set: function(pubkey, value) {
            let snapshot = fullDB._db;
            snapshot.pubkeys[pubkey] = value;
            fullDB._db = snapshot;
        },
        remove: function(pubkey) {
            let snapshot = fullDB._db;
            delete snapshot.pubkeys[pubkey];
            fullDB._db = snapshot;
        },
        has: (pubkey) => fullDB._db.pubkeys.hasOwnProperty(pubkey),
        enumerate: () => Object.keys(fullDB._db.pubkeys)
    },
    appDB: {
        get: function(appId) {
            return structuredClone(fullDB._db.apps[appId]);
        },
        set: function(appId, value) {
            let snapshot = fullDB._db;
            snapshot.apps[appId] = value;
            fullDB._db = snapshot;
        },
        remove: function(appId) {
            let snapshot = fullDB._db;
            delete snapshot.apps[appId];
            fullDB._db = snapshot;
        },
        has: (appId) => fullDB._db.apps.hasOwnProperty(appId),
        enumerate: () => Object.keys(fullDB._db.apps)
    },
    get _db() {
        return cache;
    },
    set _db(value) {
        cache = value;
    }
};

setInterval(function() {
    fs.writeFile(__dirname + "/UserDB.json", JSON.stringify(cache), () => 0);
}, 60000);

function exitHandler() {
    fs.writeFileSync(__dirname + "/UserDB.json", JSON.stringify(cache));
    process.exit(0);
}

process.on("exit", exitHandler);
process.on("SIGTERM", exitHandler);
process.on("SIGINT", exitHandler);
process.on("SIGHUP", exitHandler);
module.exports = fullDB;