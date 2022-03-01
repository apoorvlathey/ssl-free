require("dotenv").config();
const { exec } = require("child_process");
const fs = require("fs");

const accountPemFilename = process.env.ACCOUNT_PEM_FILENAME;

const main = () => {
  exec(
    `openssl genrsa -out ./keys/${accountPemFilename} 4096`,
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
