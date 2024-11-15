import * as crypto from "crypto";

interface SignatureParams {
  method: string;
  uri: string;
  queryString: string;
  headers: Record<string, string>;
  requestPayload: string;
  accessKeyId: string;
  accessKeySecret: string;
  region: string;
  service: string;
  requestDate: string;
}

function getShortDate() {
  const now = new Date();
  const year = now.getUTCFullYear(); // Get the full year
  const month = String(now.getUTCMonth() + 1).padStart(2, "0"); // Get month (0-indexed, so add 1) and pad with 0
  const day = String(now.getUTCDate()).padStart(2, "0"); // Get day and pad with 0

  return `${year}${month}${day}`;
}

function createCanonicalRequest(params: SignatureParams): string {
  const { method, uri, queryString, headers, requestPayload } = params;

  const canonicalURI = uri || "/";

  const canonicalQueryString = Object.keys(queryString)
    .sort()
    .map(
      (key) =>
        //@ts-ignore
        `${encodeURIComponent(key)}=${encodeURIComponent(queryString[key])}`
    )
    .join("&");

  const canonicalHeaders = Object.keys(headers)
    .sort()
    .map((key) => `${key.toLowerCase()}:${headers[key].trim()}\n`)
    .join("");

  const signedHeaders = Object.keys(headers)
    .sort()
    .map((key) => key.toLowerCase())
    .join(";");

  const payloadHash = crypto
    .createHash("sha256")
    .update(requestPayload)
    .digest("hex");

  return `${method}\n${canonicalURI}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
}

function createStringToSign(
  canonicalRequest: string,
  params: SignatureParams
): string {
  const { requestDate, region, service } = params;

  const algorithm = "HMAC-SHA256";
  const credentialScope = `${requestDate.slice(
    0,
    8
  )}/${region}/${service}/request`;
  const canonicalRequestHash = crypto
    .createHash("sha256")
    .update(canonicalRequest)
    .digest("hex");

  return `${algorithm}\n${requestDate}\n${credentialScope}\n${canonicalRequestHash}`;
}

function calculateSigningKey(
  accessKeySecret: string,
  requestDate: string,
  region: string,
  service: string
): Buffer {
  const kSecret = Buffer.from("HMAC" + accessKeySecret, "utf8");
  const kDate = hmac(kSecret, requestDate.slice(0, 8));
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "request");
}

function hmac(key: Buffer, data: string): Buffer {
  return crypto.createHmac("sha256", key).update(data).digest();
}

function calculateSignature(stringToSign: string, signingKey: Buffer): string {
  return hmac(signingKey, stringToSign).toString("hex");
}

function createAuthorizationHeader(
  signature: string,
  params: SignatureParams,
  signedHeaders: string
): string {
  const { accessKeyId, requestDate, region, service } = params;
  const credentialScope = `${requestDate.slice(
    0,
    8
  )}/${region}/${service}/request`;

  return `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

function calculateSignatureForRequest(params: SignatureParams): string {
  const canonicalRequest = createCanonicalRequest(params);

  const stringToSign = createStringToSign(canonicalRequest, params);

  const signingKey = calculateSigningKey(
    params.accessKeySecret,
    params.requestDate,
    params.region,
    params.service
  );

  const signature = calculateSignature(stringToSign, signingKey);

  const signedHeaders = Object.keys(params.headers)
    .sort()
    .map((key) => key.toLowerCase())
    .join(";");

  return createAuthorizationHeader(signature, params, signedHeaders);
}

const params: SignatureParams = {
  method: "GET",
  uri: "/example/api",
  queryString: "Action=SomeAction&Version=1.0",
  headers: {
    Host: "api.byteplus.com",
    "X-Date": "20231116T104027Z",
    "Content-Type": "application/json",
  },
  requestPayload: JSON.stringify({ key: "value" }),
  accessKeyId: "ak",
  accessKeySecret: "as",
  region: "ap-singapore-1",
  service: "rtc",
  requestDate: getShortDate(),
};

const authorizationHeader = calculateSignatureForRequest(params);
console.log(authorizationHeader);
