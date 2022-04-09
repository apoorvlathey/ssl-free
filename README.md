# ssl-free

Get free SSL certificate easily & quickly with this automated script

<a href="https://letsencrypt.org/">letsencrypt.org</a> provides 3 months SSL certificates for Free but the process to claim is very tedious and requires signing a bunch of strings manually via `openssl` and submitting to the website <a href="https://gethttpsforfree.com/">gethttpsforfree.com</a> which easily takes 10 mins.

This repo automates this process and you get SSL certificate in just a minute.

## Installation

0. Make sure you have `openssl` installed and using Node 17.6.0+
1. Clone this repo
2. Run `npm i` or `yarn`
3. Create new folder `keys`
4. `cp .env.example .env` and set variable values.

- `DOMAIN_PEM_FILENAME` and `ACCOUNT_PEM_FILENAME` are the names of pem files that need to be copied inside the `keys` folder.<br />
  If you don't already have these files, then you can generate them by running:<br />
  `yarn gen:accountKey` and `yarn gen:domainKey`

5. To generate the SSL certificate, run `yarn start`
6. In between the steps you'd be prompted to transfer the file generated in the `output` folder of this repo to your server at URL: `example.com/.well-known/acme-challenge/<file-generated>`

- Once you have done uploading, press enter in the terminal to continue the process.

7. The SSL certificate would get saved inside the `keys` folder on successful execution.

<br />
<b>NOTE:</b> <br >

If the script throws some error after uploading file to your server, run `yarn start` again, press enter when prompted (as you already have the same file ready on the server) and the certificate would get generated successfully.
