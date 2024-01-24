const http = require("node:http");
const fs = require("node:fs");

const ZEROS = Buffer.alloc(2048);
const DATA = fs.readFileSync("./data");
const server = http.createServer(async (req, res) => {
  if (req.url === "/down_rnd") {
    res.writeHead(200);

    let offset = 0;
    while (offset < DATA.length) {
      const chunkSize = Math.floor(Math.random() * 512 + 1);
      let data = DATA.subarray(offset, offset + chunkSize);

      if (!res.write(data)) {
        await new Promise((resolve) => res.once("drain", resolve));
      } else {
        await new Promise((resolve) => process.nextTick(resolve));
      }

      offset += chunkSize;
    }

    res.end();
  } else if (req.url === "/down") {
    res.writeHead(200);
    async function write() {
      while (true) {
        if (!res.write(ZEROS)) {
          await new Promise((resolve) => res.once("drain", resolve));
        } else {
          await new Promise((resolve) => process.nextTick(resolve));
        }
      }
    }

    write().finally(() => res.end());
  } else if (req.url === "/up") {
    console.log("up");
    req.on("data", (chunk) => console.log(chunk));
    req.on("end", () => res.end());
  }
});
server.listen(6969);
