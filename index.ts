require("dotenv").config();
const { spawn, exec } = require("child_process");
const fs = require("fs");
const readline = require("readline");
import axios from "axios";

const ASN1 = require("@lapo/asn1js");
const Base64 = require("@lapo/asn1js/base64");
const Hex = require("@lapo/asn1js/hex");
const { getRandomValues, webcrypto } = require("crypto");
const { subtle } = webcrypto;

const email = process.env.EMAIL;
const domain = process.env.DOMAIN;
const domainPemFilename = process.env.DOMAIN_PEM_FILENAME;
const accountPemFilename = process.env.ACCOUNT_PEM_FILENAME;

// global vars
const DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory";
let ACCOUNT: any = {};
let ORDER: any = {};
let DIRECTORY: any = {};
let AUTHORIZATIONS: any = {};

const getPubKey = (): Promise<string> => {
  return new Promise((resolve, reject) => {
    const openssl = spawn(
      "openssl",
      `rsa -in ./keys/${accountPemFilename} -pubout`.split(" ")
    );
    openssl.stdout.on("data", (data: any) => {
      resolve(data);
    });
  });
};

/*
 * Step 0: Let's Encrypt Directory
 */

// get the directory with links to all the other endpoints
const populateDirectory = async () => {
  try {
    const res = await axios.get(DIRECTORY_URL + "?" + cachebuster());
    DIRECTORY = res.data;
  } catch {
    throw "Let's Encrypt appears to be down. Please try again later.";
  }
};

/*
 * Step 1: Account Info
 */

// validate account info
const validateAccount = (pubkey: string) => {
  // parse account public key
  var unarmor =
    /-----BEGIN PUBLIC KEY-----([A-Za-z0-9+\/=\s]+)-----END PUBLIC KEY-----/;
  if (!unarmor.test(pubkey)) {
    throw "Your public key isn't formatted correctly.";
  }

  // find RSA modulus and exponent
  try {
    var pubkeyAsn1 = ASN1.decode(Base64.decode(unarmor.exec(pubkey)![1]));
    var modulusRaw = pubkeyAsn1.sub[1].sub[0].sub[0];
    var modulusStart = modulusRaw.header + modulusRaw.stream.pos + 1;
    var modulusEnd =
      modulusRaw.length + modulusRaw.stream.pos + modulusRaw.header;
    var modulusHex = modulusRaw.stream.hexDump(modulusStart, modulusEnd);
    var modulus = Hex.decode(modulusHex);
    var exponentRaw = pubkeyAsn1.sub[1].sub[0].sub[1];
    var exponentStart = exponentRaw.header + exponentRaw.stream.pos;
    var exponentEnd =
      exponentRaw.length + exponentRaw.stream.pos + exponentRaw.header;
    var exponentHex = exponentRaw.stream.hexDump(exponentStart, exponentEnd);
    var exponent = Hex.decode(exponentHex);
  } catch {}

  // generate the jwk header and bytes
  var jwk = {
    e: b64(new Uint8Array(exponent)),
    kty: "RSA",
    n: b64(new Uint8Array(modulus)),
  };
  var jwk_json = JSON.stringify(jwk);
  var jwk_bytes = [];
  for (var i = 0; i < jwk_json.length; i++) {
    jwk_bytes.push(jwk_json.charCodeAt(i));
  }

  // calculate thumbprint
  sha256(new Uint8Array(jwk_bytes), (hash: any, err: any) => {
    if (err) {
      throw "Thumbprint failed: " + err.message;
    }

    // update the global account object
    var registration_payload = { termsOfServiceAgreed: true };
    var account_payload = { contact: ["mailto:" + email] };
    ACCOUNT = {
      pubkey: pubkey,
      alg: "RS256",
      jwk: jwk,
      thumbprint: b64(hash),
      account_uri: undefined,

      // newAccount - account registration (or to get the account_url)
      registration_payload_json: registration_payload,
      registration_payload_b64: b64(JSON.stringify(registration_payload)),
      registration_protected_json: undefined,
      registration_protected_b64: undefined,
      registration_sig: undefined,
      registration_response: undefined,

      // account contact update
      update_payload_json: account_payload,
      update_payload_b64: b64(JSON.stringify(account_payload)),
      update_protected_json: undefined,
      update_protected_b64: undefined,
      update_sig: undefined,
      update_response: undefined,
    };

    console.log("Step 1 Done!");
  });
};

const getCSR = (): Promise<string> => {
  // generate CSR
  return new Promise((resolve, reject) => {
    exec(
      `openssl req -new -key ./keys/${domainPemFilename} -out ./keys/server.csr -subj "/CN=${domain}/emailAddress=${email}"`,
      (error: any, stdout: any, stderr: any) => {
        if (error) {
          console.log(`error: ${error.message}`);
          return;
        }
        if (stderr) {
          console.log(`stderr: ${stderr}`);
          return;
        }
        console.log(`CSR generated`);
        // get CSR
        try {
          const data = fs.readFileSync("./keys/server.csr", "utf8");
          resolve(data);
        } catch (err) {
          console.error(err);
        }
      }
    );
  });
};

const validateCSR = async (csr: string) => {
  var unarmor =
    /-----BEGIN CERTIFICATE REQUEST-----([A-Za-z0-9+\/=\s]+)-----END CERTIFICATE REQUEST-----/;
  if (!unarmor.test(csr)) {
    throw "Your CSR isn't formatted correctly.";
  }
  var csr_der = b64(new Uint8Array(Base64.decode(unarmor.exec(csr)![1])));

  // find domains in the csr
  var domains = [];
  try {
    var csrAsn1 = ASN1.decode(Base64.decode(unarmor.exec(csr)![1]));

    // look for commonName in attributes
    if (csrAsn1.sub[0].sub[1].sub) {
      var csrIds = csrAsn1.sub[0].sub[1].sub;
      for (var i = 0; i < csrIds.length; i++) {
        var oidRaw = csrIds[i].sub[0].sub[0];
        var oidStart = oidRaw.header + oidRaw.stream.pos;
        var oidEnd = oidRaw.length + oidRaw.stream.pos + oidRaw.header;
        var oid = oidRaw.stream
          .parseOID(oidStart, oidEnd, Infinity)
          .split("\n")[0];
        if (oid === "2.5.4.3") {
          var cnRaw = csrIds[i].sub[0].sub[1];
          var cnStart = cnRaw.header + cnRaw.stream.pos;
          var cnEnd = cnRaw.length + cnRaw.stream.pos + cnRaw.header;
          domains.push(cnRaw.stream.parseStringUTF(cnStart, cnEnd));
        }
      }
    }

    // look for subjectAltNames
    if (csrAsn1.sub[0].sub[3].sub) {
      // find the PKCS#9 ExtensionRequest
      var xtns = csrAsn1.sub[0].sub[3].sub;
      for (var i = 0; i < xtns.length; i++) {
        var oidRaw = xtns[i].sub[0];
        var oidStart = oidRaw.header + oidRaw.stream.pos;
        var oidEnd = oidRaw.length + oidRaw.stream.pos + oidRaw.header;
        var oid = oidRaw.stream.parseOID(oidStart, oidEnd, Infinity);
        if (oid === "1.2.840.113549.1.9.14") {
          // find any subjectAltNames
          for (
            var j = 0;
            j < xtns[i].sub[1].sub.length ? xtns[i].sub[1].sub : 0;
            j++
          ) {
            for (
              var k = 0;
              k < xtns[i].sub[1].sub[j].sub.length
                ? xtns[i].sub[1].sub[j].sub
                : 0;
              k++
            ) {
              var oidRaw = xtns[i].sub[1].sub[j].sub[k].sub[0];
              var oidStart = oidRaw.header + oidRaw.stream.pos;
              var oidEnd = oidRaw.length + oidRaw.stream.pos + oidRaw.header;
              var oid = oidRaw.stream.parseOID(oidStart, oidEnd, Infinity);
              if (oid === "2.5.29.17") {
                // add each subjectAltName
                var sans = xtns[i].sub[1].sub[j].sub[k].sub[1].sub[0].sub;
                for (var s = 0; s < sans.length; s++) {
                  var sanRaw = sans[s];
                  var tag = sanRaw.tag.tagNumber;
                  if (tag !== 2) continue; // ignore any other subjectAltName type than dNSName (2)
                  var sanStart = sanRaw.header + sanRaw.stream.pos;
                  var sanEnd =
                    sanRaw.length + sanRaw.stream.pos + sanRaw.header;
                  domains.push(sanRaw.stream.parseStringUTF(sanStart, sanEnd));
                }
              }
            }
          }
        }
      }
    }
  } catch (err) {
    throw "Failed validating CSR.";
  }

  // reject CSRs with no domains
  if (domains.length === 0) {
    throw "Couldn't find any domains in the CSR.";
  }

  // build order payload
  var finalize_payload = { csr: csr_der };
  var order_payload: any = { identifiers: [] };
  for (var i = 0; i < domains.length; i++) {
    order_payload["identifiers"].push({ type: "dns", value: domains[i] });
  }

  // update the globals
  ORDER = {
    csr_pem: csr,
    csr_der: csr_der,

    // order for identifiers
    order_payload_json: order_payload,
    order_payload_b64: b64(JSON.stringify(order_payload)),
    order_protected_json: undefined,
    order_protected_b64: undefined,
    order_sig: undefined,
    order_response: undefined,
    order_uri: undefined,

    // order finalizing
    finalize_uri: undefined,
    finalize_payload_json: finalize_payload,
    finalize_payload_b64: b64(JSON.stringify(finalize_payload)),
    finalize_protected_json: undefined,
    finalize_protected_b64: undefined,
    finalize_sig: undefined,
    finalize_response: undefined,

    // order checking after finalizing
    recheck_order_payload_json: "", // GET-as-POST has an empty payload
    recheck_order_payload_b64: "", // GET-as-POST has an empty payload
    recheck_order_protected_json: undefined,
    recheck_order_protected_b64: undefined,
    recheck_order_sig: undefined,
    recheck_order_response: undefined,

    // certificate downloading
    cert_payload_json: "", // GET-as-POST has an empty payload
    cert_payload_b64: "", // GET-as-POST has an empty payload
    cert_protected_json: undefined,
    cert_protected_b64: undefined,
    cert_sig: undefined,
    cert_response: undefined,
    cert_uri: undefined,
  };

  // set the shortest domain for the ssl test at the end
  var shortest_domain = domains[0];
  for (var d = 0; d < domains.length; d++) {
    if (shortest_domain.length > domains[d].length) {
      shortest_domain = domains[d];
    }
  }
  console.log({ shortest_domain });

  // get nonce for registration
  const nonce = await getNonce();
  // populate registration signature (payload populated in validateAccount())
  ACCOUNT["registration_protected_json"] = {
    url: DIRECTORY["newAccount"],
    alg: ACCOUNT["alg"],
    nonce: nonce,
    jwk: ACCOUNT["jwk"],
  };
  ACCOUNT["registration_protected_b64"] = b64(
    JSON.stringify(ACCOUNT["registration_protected_json"])
  );

  saveDataToSign(
    ACCOUNT["registration_protected_b64"] +
      "." +
      ACCOUNT["registration_payload_b64"]
  );
};

/*
 * Step 3a: Register Account (POST /newAccount)
 */
const validateRegistration = async (registration_sig: string) => {
  ACCOUNT["registration_sig"] = hex2b64(registration_sig);

  try {
    const res = await axios.post(
      DIRECTORY["newAccount"],
      JSON.stringify({
        protected: ACCOUNT["registration_protected_b64"],
        payload: ACCOUNT["registration_payload_b64"],
        signature: ACCOUNT["registration_sig"],
      }),
      {
        headers: {
          "Content-Type": "application/jose+json",
        },
      }
    );

    // successful registration

    // set account_uri
    ACCOUNT["account_uri"] = res.headers["location"];

    // get nonce for account update
    const nonce = await getNonce();
    // populate update signature (payload populated in validateAccount())
    ACCOUNT["update_protected_json"] = {
      url: ACCOUNT["account_uri"],
      alg: ACCOUNT["alg"],
      nonce: nonce,
      kid: ACCOUNT["account_uri"],
    };
    ACCOUNT["update_protected_b64"] = b64(
      JSON.stringify(ACCOUNT["update_protected_json"])
    );

    saveDataToSign(
      ACCOUNT["update_protected_b64"] + "." + ACCOUNT["update_payload_b64"]
    );

    console.log("Step 3a Done!");
  } catch (e: any) {
    throw "Account registration failed. Please start back at Step 1. " + e;
  }
};

/*
 * Step 3b: Update Account Contact (POST /ACCOUNT['account_uri'])
 */
const validateUpdate = async (update_sig: string) => {
  ACCOUNT["update_sig"] = hex2b64(update_sig);

  // send update request to CA account_uri
  try {
    const res = await axios.post(
      ACCOUNT["account_uri"],
      JSON.stringify({
        protected: ACCOUNT["update_protected_b64"],
        payload: ACCOUNT["update_payload_b64"],
        signature: ACCOUNT["update_sig"],
      }),
      {
        headers: {
          "Content-Type": "application/jose+json",
        },
      }
    );

    // successful update
    // get nonce for new order
    const nonce = await getNonce();
    // populate order signature (payload populated in validateCSR())
    ORDER["order_protected_json"] = {
      url: DIRECTORY["newOrder"],
      alg: ACCOUNT["alg"],
      nonce: nonce,
      kid: ACCOUNT["account_uri"],
    };
    ORDER["order_protected_b64"] = b64(
      JSON.stringify(ORDER["order_protected_json"])
    );
    saveDataToSign(
      ORDER["order_protected_b64"] + "." + ORDER["order_payload_b64"]
    );

    console.log("Step 3b Done!");
  } catch (e: any) {
    throw "Account contact update failed. Please start back at Step 1. " + e;
  }
};

/*
 * Step 3c: Create New Order (POST /newOrder)
 */
const validateOrder = async (order_sig: string): Promise<string> => {
  ORDER["order_sig"] = hex2b64(order_sig);

  // send newOrder request to CA
  try {
    const res = await axios.post(
      DIRECTORY["newOrder"],
      JSON.stringify({
        protected: ORDER["order_protected_b64"],
        payload: ORDER["order_payload_b64"],
        signature: ORDER["order_sig"],
      }),
      {
        headers: {
          "Content-Type": "application/jose+json",
        },
      }
    );

    // successful order
    // set order response and uri
    ORDER["order_response"] = res.data;
    ORDER["order_uri"] = res.headers["location"];
    ORDER["finalize_uri"] = ORDER["order_response"]["finalize"];

    // clear out any previous authorizations and challenge forms
    AUTHORIZATIONS = {};

    // add a new challenge section per authorization url
    for (var i = 0; i < ORDER["order_response"]["authorizations"].length; i++) {
      // populate the authorization object
      var auth_url = ORDER["order_response"]["authorizations"][i];
      AUTHORIZATIONS[auth_url] = {
        // load authorization
        auth_payload_json: "", // GET-as-POST has an empty payload
        auth_payload_b64: "", // GET-as-POST has an empty payload
        auth_protected_json: undefined,
        auth_protected_b64: undefined,
        auth_sig: undefined,
        auth_response: undefined,

        // python server HTTP challenge
        python_challenge_uri: undefined,
        python_challenge_object: undefined,
        python_challenge_protected_json: undefined,
        python_challenge_protected_b64: undefined,
        python_challenge_sig: undefined,
        python_challenge_response: undefined,

        // file-based HTTP challenge
        file_challenge_uri: undefined,
        file_challenge_object: undefined,
        file_challenge_protected_json: undefined,
        file_challenge_protected_b64: undefined,
        file_challenge_sig: undefined,
        file_challenge_response: undefined,

        // DNS challenge
        dns_challenge_uri: undefined,
        dns_challenge_object: undefined,
        dns_challenge_protected_json: undefined,
        dns_challenge_protected_b64: undefined,
        dns_challenge_sig: undefined,
        dns_challenge_response: undefined,

        // post-challenge authorization check
        recheck_auth_payload_json: "", // GET-as-POST has an empty payload
        recheck_auth_payload_b64: "", // GET-as-POST has an empty payload
        recheck_auth_protected_json: undefined,
        recheck_auth_protected_b64: undefined,
        recheck_auth_sig: undefined,
        recheck_auth_response: undefined,
      };
    }

    // populate the first authorization request
    await buildAuthorization(0);

    console.log("Step 3c Done!");
    return auth_url;
  } catch (e: any) {
    throw "Order failed. Please start back at Step 1. " + e;
  }
};

/*
 * Step 4a: Sign request for getting an Authorization
 */
const buildAuthorization = async (n: any) => {
  // get the authorization from global order
  var auth_url = ORDER["order_response"]["authorizations"][n];

  // get nonce for loading the authorization request
  const nonce = await getNonce();
  // populate authorization request signature (payload is empty "")
  var protected_json = {
    url: auth_url,
    alg: ACCOUNT["alg"],
    nonce: nonce,
    kid: ACCOUNT["account_uri"],
  };
  var protected_b64 = b64(JSON.stringify(protected_json));
  AUTHORIZATIONS[auth_url]["auth_protected_json"] = protected_json;
  AUTHORIZATIONS[auth_url]["auth_protected_b64"] = protected_b64;

  saveDataToSign(
    protected_b64 + "." + AUTHORIZATIONS[auth_url]["auth_payload_b64"]
  );
};

/*
 * Step 4b: Load the Authorization to get its challenges (GET-as-POST /auth['url'])
 */
const validateAuthorization = async (auth_url: string, auth_sig: string) => {
  // validate the signature
  AUTHORIZATIONS[auth_url]["auth_sig"] = hex2b64(auth_sig);

  // send request to CA to get the authorization
  const res = await axios.post(
    auth_url,
    JSON.stringify({
      protected: AUTHORIZATIONS[auth_url]["auth_protected_b64"],
      payload: AUTHORIZATIONS[auth_url]["auth_payload_b64"],
      signature: AUTHORIZATIONS[auth_url]["auth_sig"],
    }),
    {
      headers: {
        "Content-Type": "application/jose+json",
      },
    }
  );

  var auth_obj = res.data;
  AUTHORIZATIONS[auth_url]["auth_response"] = auth_obj;

  // clear stale challenge objects
  AUTHORIZATIONS[auth_url]["file_challenge_uri"] = undefined;
  AUTHORIZATIONS[auth_url]["file_challenge_object"] = undefined;

  // update challenges in global
  var challenge_dicts = AUTHORIZATIONS[auth_url]["auth_response"]["challenges"];
  for (var i = 0; i < challenge_dicts.length; i++) {
    var challenge_dict = challenge_dicts[i];

    // HTTP challenge
    if (challenge_dict["type"] === "http-01") {
      AUTHORIZATIONS[auth_url]["file_challenge_uri"] = challenge_dict["url"];
      AUTHORIZATIONS[auth_url]["file_challenge_object"] = challenge_dict;
    }
  }

  // file-based option data
  if (AUTHORIZATIONS[auth_url]["file_challenge_object"] !== undefined) {
    // populate values
    var token = AUTHORIZATIONS[auth_url]["file_challenge_object"]["token"];

    var keyauth = token + "." + ACCOUNT["thumbprint"];
    var echo =
      'echo -n "' +
      keyauth +
      '" > /path/to/www/.well-known/acme-challenge/' +
      token;
    console.log({ echo });

    fs.writeFileSync(`./output/${token}`, keyauth);

    // set data attributes
    var challenge_url = AUTHORIZATIONS[auth_url]["file_challenge_object"][
      "url"
    ] as string;

    return challenge_url;
  }

  return "";
};

/*
 * Step 4c: Confirm Challenge
 */
const confirmChallenge = async (auth_url: string, challenge_url: string) => {
  var option = "file";

  // get nonce for challenge
  const nonce = await getNonce();
  // populate challenge signature (payload is empty {})
  var protected_json = {
    url: challenge_url,
    alg: ACCOUNT["alg"],
    nonce: nonce,
    kid: ACCOUNT["account_uri"],
  };
  var protected_b64 = b64(JSON.stringify(protected_json));
  AUTHORIZATIONS[auth_url][option + "_protected_json"] = protected_json;
  AUTHORIZATIONS[auth_url][option + "_protected_b64"] = protected_b64;

  saveDataToSign(protected_b64 + "." + b64(JSON.stringify({})));

  console.log("Step 4a Done!");
};

/*
 * Step 4d: Verify Ownership (POST /challenge['url'], ...)
 */
const validateChallenge = async (
  auth_url: string,
  challenge_url: string,
  sig_input: string
) => {
  // find the relevant resources
  var option = "file";

  var challenge_sig = hex2b64(sig_input);
  AUTHORIZATIONS[auth_url][option + "_challenge_sig"] = challenge_sig;

  // submit challenge to CA
  try {
    const res = await axios.post(
      challenge_url,
      JSON.stringify({
        protected: AUTHORIZATIONS[auth_url][option + "_protected_b64"],
        payload: b64(JSON.stringify({})), // always empty payload
        signature: AUTHORIZATIONS[auth_url][option + "_challenge_sig"],
      }),
      {
        headers: {
          "Content-Type": "application/jose+json",
        },
      }
    );

    // successful challenge submission
    // set challenge response
    AUTHORIZATIONS[auth_url][option + "_challenge_response"] = res.data;

    // get nonce for checking the authorization status
    const nonce = await getNonce();
    // populate authorization request signature (payload is empty "")
    var protected_json = {
      url: auth_url,
      alg: ACCOUNT["alg"],
      nonce: nonce,
      kid: ACCOUNT["account_uri"],
    };
    var protected_b64 = b64(JSON.stringify(protected_json));
    AUTHORIZATIONS[auth_url]["recheck_auth_protected_json"] = protected_json;
    AUTHORIZATIONS[auth_url]["recheck_auth_protected_b64"] = protected_b64;

    saveDataToSign(
      protected_b64 + "." + AUTHORIZATIONS[auth_url]["recheck_auth_payload_b64"]
    );

    console.log("Step 4d Done!");
  } catch (e: any) {
    throw "Challenge submission failed. Please start back at Step 1. " + e;
  }
};

/*
 * Step 4e: Check authorization status after submitting the challenge (GET-as-POST /auth['url'])
 */
const checkAuthorization = async (auth_url: string, sig_input: string) => {
  var recheck_auth_sig = hex2b64(sig_input);
  AUTHORIZATIONS[auth_url]["recheck_auth_sig"] = recheck_auth_sig;

  // send request to CA to get the authorization
  try {
    const res = await axios.post(
      auth_url,
      JSON.stringify({
        protected: AUTHORIZATIONS[auth_url]["recheck_auth_protected_b64"],
        payload: AUTHORIZATIONS[auth_url]["recheck_auth_payload_b64"],
        signature: AUTHORIZATIONS[auth_url]["recheck_auth_sig"],
      }),
      {
        headers: {
          "Content-Type": "application/jose+json",
        },
      }
    );

    // set recheck_auth response
    var auth_obj = res.data;
    AUTHORIZATIONS[auth_url]["recheck_auth_response"] = auth_obj;

    // authorization valid, so proceed to next set of challenges or finalize
    if (auth_obj["status"] === "valid") {
      // find the next authorization that doesn't have a recheck status
      var next_auth_i = undefined;
      for (
        var i = 0;
        i < ORDER["order_response"]["authorizations"].length;
        i++
      ) {
        var a_url = ORDER["order_response"]["authorizations"][i];
        if (AUTHORIZATIONS[a_url]["recheck_auth_response"] === undefined) {
          next_auth_i = i;
          break;
        }
      }

      // all authorizations done! so finalize the order

      // get nonce for finalizing
      const nonce = await getNonce();
      // populate order finalize signature (payload populated in validateCSR())
      ORDER["finalize_protected_json"] = {
        url: ORDER["finalize_uri"],
        alg: ACCOUNT["alg"],
        nonce: nonce,
        kid: ACCOUNT["account_uri"],
      };
      ORDER["finalize_protected_b64"] = b64(
        JSON.stringify(ORDER["finalize_protected_json"])
      );

      saveDataToSign(
        ORDER["finalize_protected_b64"] + "." + ORDER["finalize_payload_b64"]
      );

      // proceed finalize order
      console.log("Step 4e Done!");
    }
    // authorization failed, so show an error
    else {
      throw (
        "Domain challenge failed. Please start back at Step 1. " +
        JSON.stringify(auth_obj)
      );
    }
  } catch (e: any) {
    // error loading authorization
    throw "Loading challenge status failed. Please start back at Step 1. " + e;
  }
};

/*
 * Step 4f: Issue Certificate (POST /order['finalize'])
 */
const validateFinalize = async (finalize_sig: string) => {
  ORDER["finalize_sig"] = hex2b64(finalize_sig);

  // send update request to CA finalize_uri
  try {
    const res = await axios.post(
      ORDER["finalize_uri"],
      JSON.stringify({
        protected: ORDER["finalize_protected_b64"],
        payload: ORDER["finalize_payload_b64"],
        signature: ORDER["finalize_sig"],
      }),
      {
        headers: {
          "Content-Type": "application/jose+json",
        },
      }
    );

    // successful finalizing the order

    // set finalize response
    ORDER["finalize_response"] = res.data;

    // get nonce for rechecking the order
    const nonce = await getNonce();
    // populate recheck_order signature
    ORDER["recheck_order_protected_json"] = {
      url: ORDER["order_uri"],
      alg: ACCOUNT["alg"],
      nonce: nonce,
      kid: ACCOUNT["account_uri"],
    };
    ORDER["recheck_order_protected_b64"] = b64(
      JSON.stringify(ORDER["recheck_order_protected_json"])
    );

    saveDataToSign(
      ORDER["recheck_order_protected_b64"] +
        "." +
        ORDER["recheck_order_payload_b64"]
    );

    // complete step 4f
    console.log("Step 4f Done!");
  } catch (e: any) {
    // error registering
    throw "Finalizing failed. Please start back at Step 1. " + e;
  }
};

/*
 * Step 4g: Check Order Status (GET-as-POST /order['order_uri'])
 */
const recheckOrder = async (recheck_order_sig: string) => {
  ORDER["recheck_order_sig"] = hex2b64(recheck_order_sig);

  // send update request to CA finalize_uri
  try {
    const res = await axios.post(
      ORDER["order_uri"],
      JSON.stringify({
        protected: ORDER["recheck_order_protected_b64"],
        payload: ORDER["recheck_order_payload_b64"],
        signature: ORDER["recheck_order_sig"],
      }),
      {
        headers: {
          "Content-Type": "application/jose+json",
        },
      }
    );

    // successful finalizing the order

    // set recheck_order response
    var order = res.data;
    ORDER["recheck_order_response"] = order;

    if (order["status"] === "valid") {
      // set the certificate uri
      ORDER["cert_uri"] = order["certificate"];

      // get nonce for getting the certificate
      const nonce = await getNonce();
      // populate cert retrieval signature
      ORDER["cert_protected_json"] = {
        url: ORDER["cert_uri"],
        alg: ACCOUNT["alg"],
        nonce: nonce,
        kid: ACCOUNT["account_uri"],
      };
      ORDER["cert_protected_b64"] = b64(
        JSON.stringify(ORDER["cert_protected_json"])
      );

      saveDataToSign(
        ORDER["cert_protected_b64"] + "." + ORDER["cert_payload_b64"]
      );

      console.log("Step 4g Done!");
    }

    // order invalid
    else {
      throw "Order processing failed. Please start back at Step 1. " + res.data;
    }
  } catch (e: any) {
    // error checking order
    throw "Account registration failed. Please start back at Step 1. " + e;
  }
};

/*
 * Step 4h: Get Certificate (GET-as-POST /order['cert_uri'])
 */
const getCertificate = async (cert_sig: string) => {
  ORDER["cert_sig"] = hex2b64(cert_sig);

  // send update request to CA finalize_uri
  try {
    const res = await axios.post(
      ORDER["cert_uri"],
      JSON.stringify({
        protected: ORDER["cert_protected_b64"],
        payload: ORDER["cert_payload_b64"],
        signature: ORDER["cert_sig"],
      }),
      {
        headers: {
          "Content-Type": "application/jose+json",
        },
      }
    );

    // successful finalizing the order

    // format cert into PEM format
    fs.writeFileSync(`./keys/cert_${domain}_${+new Date()}.txt`, res.data);
    console.log("CERTIFICATE SAVED!");
  } catch (e: any) {
    // error geting certificate
    throw "Certificate retrieval failed. Please start back at Step 1. " + e;
  }
};

const signDataToSign = (): Promise<string> => {
  return new Promise((resolve, reject) => {
    exec(
      `openssl dgst -sha256 -hex -sign ./keys/${accountPemFilename} ./temp/dataToSign.txt`,
      (error: any, stdout: any, stderr: any) => {
        if (error) {
          console.log(`error: ${error.message}`);
          return;
        }
        if (stderr) {
          console.log(`stderr: ${stderr}`);
          return;
        }

        // stdout format:
        // `RSA-SHA256(./temp/dataToSign.txt)= 99876....\n`
        const signature = (stdout as string).split(" ")[1].split("\n")[0];
        resolve(signature);
      }
    );
  });
};

// url-safe base64 encoding
function b64(bytes: any) {
  var str64 =
    typeof bytes === "string"
      ? btoa(bytes)
      : btoa(String.fromCharCode.apply(null, bytes));
  return str64.replace(/\//g, "_").replace(/\+/g, "-").replace(/=/g, "");
}

// SHA-256 shim for standard promise-based
function sha256(bytes: any, callback: any) {
  var hash = subtle.digest({ name: "SHA-256" }, bytes);
  hash
    .then(function (result: any) {
      callback(new Uint8Array(result), undefined);
    })
    .catch(function (error: any) {
      callback(undefined, error);
    });
}

// parse openssl hex output
var OPENSSL_HEX = /(?:\(stdin\)= |)([a-f0-9]{512,1024})/;
function hex2b64(hex: string) {
  if (!OPENSSL_HEX.test(hex)) {
    return null;
  }
  hex = OPENSSL_HEX.exec(hex)![1];
  var bytes = [];
  while (hex.length >= 2) {
    bytes.push(parseInt(hex.substring(0, 2), 16));
    hex = hex.substring(2, hex.length);
  }
  return b64(new Uint8Array(bytes));
}

// url-safe base64 encoding
function cachebuster() {
  return "cachebuster=" + b64(getRandomValues(new Uint8Array(8)));
}

// helper function to get a nonce via an ajax request to the ACME directory
const getNonce = async () => {
  try {
    const res = await axios.get(DIRECTORY["newNonce"] + "?" + cachebuster());
    return res.headers["replay-nonce"];
  } catch (e: any) {
    throw e;
  }
};

const saveDataToSign = (data: string) => {
  fs.writeFileSync("./temp/dataToSign.txt", data);
};

const waitForUserInput = () => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) =>
    rl.question("Press any key to continue", (ans: string) => {
      rl.close();
      resolve(ans);
    })
  );
};

const main = async () => {
  await populateDirectory();

  const pubKey = await getPubKey();
  validateAccount(pubKey);

  const csr = await getCSR();
  await validateCSR(csr);

  // dataToSign.txt gets updated in each step
  const registration_sig = await signDataToSign();
  await validateRegistration(registration_sig);

  const update_sig = await signDataToSign();
  await validateUpdate(update_sig);

  const order_sig = await signDataToSign();
  const auth_url = await validateOrder(order_sig);
  const auth_sig = await signDataToSign();
  //!! File challenge info returned here!
  const challenge_url = await validateAuthorization(auth_url, auth_sig);
  await waitForUserInput();

  await confirmChallenge(auth_url, challenge_url);

  const sig_input = await signDataToSign();
  await validateChallenge(auth_url, challenge_url, sig_input);

  const new_sig_input = await signDataToSign();
  await checkAuthorization(auth_url, new_sig_input);

  const finalize_sig = await signDataToSign();
  await validateFinalize(finalize_sig);

  const recheck_order_sig = await signDataToSign();
  await recheckOrder(recheck_order_sig);

  const cert_sig = await signDataToSign();
  await getCertificate(cert_sig);
};
main();
