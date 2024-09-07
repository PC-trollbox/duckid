const db = require("./index");
const repl = require("repl");

let replServer = repl.start("db> ");
replServer.context.db = db;
replServer.on("exit", () => process.exit(0));