# DuckID

This is DuckID, a service that lets you log into other services that implement it.

To self-host, you need to copy db/blank.json to db/UserDB.json, install the dependencies, and run index.js with NodeJS:

```bash
cp db/blank.json db/UserDB.json # Linux command for copying
npm i
node index.js
```

Official server: https://duckid.pcprojects.tk