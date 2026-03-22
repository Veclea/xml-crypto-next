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

  // 保持参数类型为 crypto.BinaryLike 以匹配父类接口
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      if (!(typeof privateKey === "string" || Buffer.isBuffer(privateKey))) {
        throw new Error("keys must be strings or buffers");
      }

      // Ed25519 需要二进制数据进行签名。
      // 如果输入是字符串，必须转换为 Buffer。
      const dataToSign = typeof signedInfo === 'string'
        ? Buffer.from(signedInfo, 'utf8')
        : signedInfo;

      // crypto.sign 对于 Ed25519 第一个参数传 null
      // 此时 dataToSign 保证是 ArrayBufferView 或 ArrayBuffer
      const signature = crypto.sign(null, dataToSign, privateKey);

      return signature.toString('base64');
    },
  );

  // 保持参数类型为 string (根据报错信息，父类 verifySignature 的第一个参数可能是 string 或 BinaryLike)
  // 查看报错信息：Type '{ (material: BinaryData... }' is not assignable to type '{ (material: string... }'
  // 这说明你的基类 SignatureAlgorithm 定义 verifySignature 第一个参数是 string!
  // 我们需要同时支持 string 和 BinaryLike 以确保兼容性，或者严格按照基类定义。
  // 通常 XML 签名验证时，传入的是规范化后的 XML 字符串或 Buffer。
  // 为了安全起见，我们接受 crypto.BinaryLike 并在内部处理，但为了通过 TS 检查，
  // 我们必须让参数类型 >= 父类定义的類型。
  // 如果父类定义是 string，我们就写 string | Buffer | ... 或者直接 BinaryLike

  verifySignature = createOptionalCallbackFunction(
    (material: crypto.BinaryLike, key: crypto.KeyLike, signatureValue: string): boolean => {
      if (!(typeof key === "string" || Buffer.isBuffer(key))) {
        throw new Error("keys must be strings or buffers");
      }

      // 将 Base64 签名转换为 Buffer
      const signature = Buffer.from(signatureValue, 'base64');

      // 同样，如果 material 是字符串，转换为 Buffer
      const dataToVerify = typeof material === 'string'
        ? Buffer.from(material, 'utf8')
        : material;

      // crypto.verify 对于 Ed25519 第一个参数传 null
      return crypto.verify(null, dataToVerify, key, signature);
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2007/05/xmldsig-more#eddsa-ed25519";
  };
}

export class Ed488 implements SignatureAlgorithm {

  // 保持参数类型为 crypto.BinaryLike 以匹配父类接口
  getSignature = createOptionalCallbackFunction(
    (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      if (!(typeof privateKey === "string" || Buffer.isBuffer(privateKey))) {
        throw new Error("keys must be strings or buffers");
      }

      // Ed25519 需要二进制数据进行签名。
      // 如果输入是字符串，必须转换为 Buffer。
      const dataToSign = typeof signedInfo === 'string'
        ? Buffer.from(signedInfo, 'utf8')
        : signedInfo;

      // crypto.sign 对于 Ed25519 第一个参数传 null
      // 此时 dataToSign 保证是 ArrayBufferView 或 ArrayBuffer
      const signature = crypto.sign(null, dataToSign, privateKey);

      return signature.toString('base64');
    },
  );

  // 保持参数类型为 string (根据报错信息，父类 verifySignature 的第一个参数可能是 string 或 BinaryLike)
  // 查看报错信息：Type '{ (material: BinaryData... }' is not assignable to type '{ (material: string... }'
  // 这说明你的基类 SignatureAlgorithm 定义 verifySignature 第一个参数是 string!
  // 我们需要同时支持 string 和 BinaryLike 以确保兼容性，或者严格按照基类定义。
  // 通常 XML 签名验证时，传入的是规范化后的 XML 字符串或 Buffer。
  // 为了安全起见，我们接受 crypto.BinaryLike 并在内部处理，但为了通过 TS 检查，
  // 我们必须让参数类型 >= 父类定义的類型。
  // 如果父类定义是 string，我们就写 string | Buffer | ... 或者直接 BinaryLike

  verifySignature = createOptionalCallbackFunction(
    (material: crypto.BinaryLike, key: crypto.KeyLike, signatureValue: string): boolean => {
      if (!(typeof key === "string" || Buffer.isBuffer(key))) {
        throw new Error("keys must be strings or buffers");
      }

      // 将 Base64 签名转换为 Buffer
      const signature = Buffer.from(signatureValue, 'base64');

      // 同样，如果 material 是字符串，转换为 Buffer
      const dataToVerify = typeof material === 'string'
        ? Buffer.from(material, 'utf8')
        : material;

      // crypto.verify 对于 Ed25519 第一个参数传 null
      return crypto.verify(null, dataToVerify, key, signature);
    },
  );

  getAlgorithmName = () => {
    return "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448";
  };
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
