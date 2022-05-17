import {  NtlmClient } from "./index"

const request = new NtlmClient();
request.request({
    url: 'https://ntlm.protected.data/collection',
    method: 'PUT',
    debug: false,
    disableRedirect: false,
    body: { foo: 'bar' },
    headers: {
      'content-type': 'application/json'
    }
  }, 'user', 'pass', 'workstation', 'domain')
  .then((response) => {
    console.log('Content body of the response', response.body);
    console.log('Headers of the response', response.headers);
    console.log('StatusCode of the response', response.status);
  })
  .catch((error) => {
    console.error(error)
  })