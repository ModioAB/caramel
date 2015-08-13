define(['rsa', 'x509', 'pki', 'sha256', 'pkcs12', 'asn1'],
function(rsa, x509, pki, sha256, pkcs12, asn1) {

  function create() {
    var caUrl;
    var storage = localStorage;
    var storageKeyPrefix = 'caramel-request-';
    var subject = [];
    var progressCallbacks = {};
    var that;

    function caUrlSetter(arg) {
      caUrl = arg;
      return that;
    }

    function storageSetter(arg) {
      storage = arg;
      return that;
    }

    function storageKeyPrefixSetter(arg) {
      storageKeyPrefix = arg;
      return that;
    }

    function subjectSetter(arg) {
      subject = arg.map(function(pair) {
        return {shortName: pair[0], value: pair[1]};
      });
      return that;
    }

    function progressCallbacksSetter(arg) {
      progressCallbacks = arg;
      return that;
    }

    function getBundleDataURI() {
      var privateKey;
      var promise = getKeyPair()
            .then(function(keyPair) {
              privateKey = keyPair.privateKey;
              return keyPair;
            })
            .then(getCSR)
            .then(function(csrPEM) {
              progress('csrData', dataURI('application/pkcs10', csrPEM));
              var hash = sha256Hex(csrPEM);
              progress('requestUri', caUrl + hash);
              return requestCertificate(caUrl + hash, csrPEM);
            })
            .then(function(crtPEM) {
              progress('certificateData',
                       dataURI('application/pkix-cert', crtPEM));
              var certificate = pki().certificateFromPem(crtPEM);
              var p12ASN1 =
                    pkcs12().toPkcs12Asn1(privateKey, certificate, null);
              var p12DER = asn1().toDer(p12ASN1).getBytes();
              return dataURI('application/x-pkcs12', p12DER);
            });
      return promise;
    }

    function getKeyPair() {
      var key = storageGet('privateKey');
      if (!key) {
        progress('generatingKey');
        var keyPair = rsa().generateKeyPair();
        var privateKey =
              removeCarriageReturns(pki().privateKeyToPem(keyPair.privateKey));
        var publicKey =
              removeCarriageReturns(pki().publicKeyToPem(keyPair.publicKey));
        storageSet('privateKey', privateKey);
        storageSet('publicKey', publicKey);
      } else {
        progress('foundKey');
      }
      var result = {
        privateKey: pki().privateKeyFromPem(storageGet('privateKey')),
        publicKey: pki().publicKeyFromPem(storageGet('publicKey'))
      };
      return Promise.resolve(result);
    }

    function getCSR(keyPair) {
      var csrPem = storageGet('csr');
      if (!csrPem) {
        progress('generatingCsr');
        var csr = x509().createCertificationRequest();
        csr.publicKey = keyPair.publicKey;
        csr.setSubject(subject);
        csr.sign(keyPair.privateKey);
        csrPem = removeCarriageReturns(x509().certificationRequestToPem(csr));
        storageSet('csr', csrPem);
      } else {
        progress('foundCsr');
      }
      var result = storageGet('csr');
      return Promise.resolve(result);
    }

    function requestCertificate(url, csr) {
      progress('getCertificate');
      return request('GET', url)
        .then(function(xhr) {
          if (xhr.status === 404) {
            progress('postCsr');
            return request('POST', url, csr)
              .then(function(xhr) {
                if (xhr.status >= 200 && xhr.status < 300) {
                  progress('postedCsr');
                  return requestCertificate(url, csr);
                } else {
                  progress('xhrError', xhr);
                  throw xhr;
                }
              });
          } else if (xhr.status === 200) {
            progress('gotCertificate');
            return xhr.responseText;
          } else {
            progress('waitingForCertificate');
            return waitMs(15000)
              .then(function() {
                return requestCertificate(url, csr);
              });
          }
        });
    }

    function storageGet(key) {
      return storage.getItem(storageKeyPrefix + key);
    }

    function storageSet(key, value) {
      storage.setItem(storageKeyPrefix + key, value);
    }

    function progress(name) {
      if (name in progressCallbacks) {
        progressCallbacks[name].apply(null, arguments);
      }
    }

    that = {
      caUrl: caUrlSetter,
      storage: storageSetter,
      storageKeyPrefix: storageKeyPrefixSetter,
      subject: subjectSetter,
      progressCallbacks: progressCallbacksSetter,
      getBundleDataURI: getBundleDataURI
    };
    return that;
  }

  function arrayBufferToString(buffer) {
    var result_string = '';
    var view = new Uint8Array(buffer);

    for (var i = 0; i < view.length; i++) {
      result_string += String.fromCharCode(view[i]);
    }

    return result_string;
  }

  function removeCarriageReturns(str) {
    return str.replace(/\r/g, '');
  }

  function sha256Hex(str) {
    return sha256().create().update(str).digest().toHex();
  }

  function request(method, url, data) {
    return new Promise(function(resolve) {
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
          resolve(xhr);
        }
      };
      xhr.open(method, url, true);
      xhr.send(data);
    });
  }

  function waitMs(delayMs) {
    return new Promise(function(resolve) {
      setTimeout(resolve, delayMs);
    });
  }

  function dataURI(contentType, data) {
    if (data instanceof ArrayBuffer) {
      data = arrayBufferToString(data);
    }
    return 'data:' + contentType + ';base64,' + btoa(data);
  }

  return { create: create };
});
