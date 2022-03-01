require("dotenv").config();
const { exec } = require("child_process");
const fs = require("fs");

const domainPemFilename = process.env.DOMAIN_PEM_FILENAME;

const main = () => {
  exec(
    `openssl genrsa -out ./keys/${domainPemFilename} 4096`,
    (error: any, stdout: any, stderr: any) => {
      if (error) {
        console.log(`error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.log(`stderr: ${stderr}`);
        return;
      }
      console.log("Key generated");
    }
  );
};
main();
