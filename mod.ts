import {
  signingSecret,
  signingVersion,
} from "./_constants.ts";

import {
  Status,
  HmacSha256,
  secureCompare,
} from "./deps.ts";

export const verifySlackRequest = (headers: Headers, body: string): Status => {
  if (!headers.has("X-Slack-Signature")) return Status.Unauthorized;
  if (!headers.has("X-Slack-Request-Timestamp")) return Status.BadRequest;
  const verificationString = `${signingVersion}:${headers.get(
    "X-Slack-Request-Timestamp",
  )!}:${body}`;
  const verificationDigest = `${signingVersion}=${
    (new HmacSha256(signingSecret)).update(verificationString).hex()
  }`;
  if (
    !secureCompare(headers.get("X-Slack-Signature")!, verificationDigest)
  ) {
    return Status.Forbidden;
  }
  return Status.OK;
};
