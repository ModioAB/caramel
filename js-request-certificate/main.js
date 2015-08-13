(function() {
  require.config({
    baseUrl: 'forge/js'
  });

  require(['./caramel-request.js'], function(caramelRequest) {
    function addResult(description, uri) {
      var div = document.createElement('div');
      if (uri !== undefined) {
        var link = document.createElement('a');
        link.setAttribute('href', uri);
        link.textContent = description;
        div.appendChild(link);
      } else {
        div.textContent = description;
      }
      document.querySelector('#result').appendChild(div);
    }

    function performRequest() {
      button.disabled = true;

      var caUrl = document.querySelector('[name=ca-url]').value;
      var certificateRequest = caramelRequest.create();
      certificateRequest
        .caUrl(caUrl)
        .storage(localStorage)
        .subject([['C', 'SE'], ['O', 'Gurk'], ['CN', 'Gurk']]);

      certificateRequest
        .progressCallbacks({
          requestUri: function(name, uri) { addResult('Request URI', uri); },
          generatingKey: function() { addResult('Generating keypair'); },
          foundKey: function() { addResult('Found keypair in localStorage'); },
          generatingCsr: function() { addResult('Generating CSR'); },
          foundCsr: function() { addResult('Found CSR in localStorage'); },
          csrData: function(name, uri) { addResult('CSR data', uri); },
          getCertificate: function() { addResult('Requesting certificate'); },
          postCsr: function() { addResult('CSR not posted, posting'); },
          xhrError: function(name, xhr) {
            addResult('Request error: ' +
                      xhr.status + ' ' + xhr.statusText + ' - ' + xhr.response);
            console.error(xhr);
          },
          gotCertificate: function() { addResult('Received certificate'); },
          waitingForCertificate: function() {
            addResult('Certificate not signed, waiting ...');
          },
          certificateData: function(name, uri) {
            addResult('Certificate', uri);
          }
        });

      certificateRequest.getBundleDataURI()
        .then(function(uri) {
          addResult('PKCS#12 bundle', uri);
        })
        .catch (function(error) {
          console.error(error);
          addResult('Failed: ' + error);
        });
    }

    var button = document.querySelector('#request');
    button.addEventListener('click', performRequest, false);
    button.disabled = false;
  });
}());
