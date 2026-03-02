import * as crypto from "crypto";
import { type SignatureAlgorithm, createOptionalCallbackFunction } from "./types";

export class RsaSha1 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA1");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA1");
      verifier.update(material);
      const res = verifier.verify(key, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  };
}

export class RsaSha256 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(material);
      const res = verifier.verify(key, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  };
}

export class RsaSha256Mgf1 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      if (!(typeof privateKey === "string" || Buffer.isBuffer(privateKey))) {
        throw new Error("keys must be strings or buffers");
      }
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signedInfo);
      const res = signer.sign(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        "base64",
      );

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      if (!(typeof key === "string" || Buffer.isBuffer(key))) {
        throw new Error("keys must be strings or buffers");
      }
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(material);
      const res = verifier.verify(
        {
          key: key,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signatureValue,
        "base64",
      );

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
  };
}
export class RsaSha384 implements SignatureAlgorithm {
    getSignature = createOptionalCallbackFunction(
        (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
            const signer = crypto.createSign("RSA-SHA384");
            signer.update(signedInfo);
            const res = signer.sign(privateKey, "base64");

            return res;
        },
    );

    verifySignature = createOptionalCallbackFunction(
        (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
            const verifier = crypto.createVerify("RSA-SHA384");
            verifier.update(material);
            const res = verifier.verify(key, signatureValue, "base64");

            return res;
        },
    );

    getAlgorithmName = () => {
        return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    };
}

export class RsaSha384Mgf1 implements SignatureAlgorithm {
    getSignature = createOptionalCallbackFunction(
        (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
            if (!(typeof privateKey === "string" || Buffer.isBuffer(privateKey))) {
                throw new Error("keys must be strings or buffers");
            }
            const signer = crypto.createSign("RSA-SHA384");
            signer.update(signedInfo);
            const res = signer.sign(
                {
                    key: privateKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
                },
                "base64",
            );

            return res;
        },
    );

    verifySignature = createOptionalCallbackFunction(
        (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
            if (!(typeof key === "string" || Buffer.isBuffer(key))) {
                throw new Error("keys must be strings or buffers");
            }
            const verifier = crypto.createVerify("RSA-SHA384");
            verifier.update(material);
            const res = verifier.verify(
                {
                    key: key,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
                },
                signatureValue,
                "base64",
            );

            return res;
        },
    );

    getAlgorithmName = () => {
        return "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
    };
}
export class RsaSha512 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signer = crypto.createSign("RSA-SHA512");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createVerify("RSA-SHA512");
      verifier.update(material);
      const res = verifier.verify(key, signatureValue, "base64");

      return res;
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  };
}
export class RsaSha512Mgf1 implements SignatureAlgorithm {
    getSignature = createOptionalCallbackFunction(
        (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
            if (!(typeof privateKey === "string" || Buffer.isBuffer(privateKey))) {
                throw new Error("keys must be strings or buffers");
            }
            const signer = crypto.createSign("RSA-SHA512");
            signer.update(signedInfo);
            const res = signer.sign(
                {
                    key: privateKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
                },
                "base64",
            );

            return res;
        },
    );

    verifySignature = createOptionalCallbackFunction(
        (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
            if (!(typeof key === "string" || Buffer.isBuffer(key))) {
                throw new Error("keys must be strings or buffers");
            }
            const verifier = crypto.createVerify("RSA-SHA512");
            verifier.update(material);
            const res = verifier.verify(
                {
                    key: key,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
                },
                signatureValue,
                "base64",
            );

            return res;
        },
    );

    getAlgorithmName = () => {
        return "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
    };
}
export class Ed25519 implements SignatureAlgorithm {
    getSignature = createOptionalCallbackFunction<string, [crypto.BinaryLike, crypto.KeyLike]>(
        (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
            // 确保 signedInfo 转换为 Buffer
            const bufferData = crypto.BinaryLikeToBuffer(signedInfo);

            if (!(typeof privateKey === "string" || Buffer.isBuffer(privateKey))) {
                throw new Error("keys must be strings or buffers");
            }

            const signature = crypto.sign('ed25519', bufferData, privateKey);
            return signature.toString('base64');
        }
    );

    verifySignature = createOptionalCallbackFunction<boolean, [string, crypto.KeyLike, string]>(
        (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
            // 将 material 转换为 Buffer
            const bufferMaterial = crypto.BinaryLikeToBuffer(material);

            if (!(typeof key === "string" || Buffer.isBuffer(key))) {
                throw new Error("keys must be strings or buffers");
            }

            const signature = Buffer.from(signatureValue, 'base64');
            return crypto.verify('ed25519', bufferMaterial, key, signature);
        }
    );

    getAlgorithmName = () => {
        return "http://www.w3.org/2007/05/xmldsig-more#eddsa-ed25519";
    };
}

// 添加辅助函数将 BinaryLike 转换为 Buffer
declare module "crypto" {
    export function BinaryLikeToBuffer(data: crypto.BinaryLike): Buffer;
}


export class HmacSha1 implements SignatureAlgorithm {
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signer = crypto.createHmac("SHA1", privateKey);
      signer.update(signedInfo);
      const res = signer.digest("base64");

      return res;
    },
  );

  verifySignature = createOptionalCallbackFunction(
    (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifier = crypto.createHmac("SHA1", key);
      verifier.update(material);
      const res = verifier.digest("base64");

      // Use constant-time comparison to prevent timing attacks (CWE-208)
      // See: https://github.com/node-saml/xml-crypto/issues/522
      try {
        return crypto.timingSafeEqual(
          Buffer.from(res, "base64"),
          Buffer.from(signatureValue, "base64"),
        );
      } catch (e) {
        // timingSafeEqual throws if buffer lengths don't match
        return false;
      }
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  };
}
