// ICON PDS for Nia Client
const request = require('request');
const jwk_to_pem = require('jwk-to-pem');
const JWK = require('../jwk');
const JWE = require('../jwe');
const pds_config = require('config').get('icon')


const server_check_message = {
    uri: pds_config.get('uri'),
    method: 'GET'
}


const validation_request_message = {
    uri: pds_config.get('uri') + '/pds/validation',
    method: pds_config.get('method'),
    headers: { Authorization: '' }
}


async function request_to_pds(payload, call_back) {
    const pem = jwk_to_pem(pds_config.get('server_key'))
    const key = await JWK.asKey(pem, "pem");

    const buffer = Buffer.from(JSON.stringify(payload))
    const compact = await JWE.createEncrypt(
        { format: "compact", contentAlg: "A128GCM", fields: { alg: "ECDH-ES+A128KW" } }, key).update(buffer).final()
    let encrypted = compact[0]
    let cek = compact[1]

    let request_msg = validation_request_message
    request_msg.headers.Authorization = encrypted

    request.post(request_msg, async function (err, httpResponse, body) {
        let response = body.replace(/\"/gi, "")
        const decrypted = await JWE.createDecrypt(cek).decrypt(response)
        const decrypted_payload = decrypted.payload.toString()
        call_back(decrypted_payload)
    })
}


async function validation(data, call_back) {
    console.log("Request Validation to PDS.")

    let request_payload = {
        type: "VALIDATE_VC_REQUEST",
        iat: Math.floor(Date.now() / 1000),
        vc_type: "1",
        keys: ["email", "phone"],
        data: data
    }

    await request_to_pds(request_payload, call_back)
}

function server_check() {
    console.log("PDS Server is running?")

    request.get(server_check_message, function(err,httpResponse,body) {
        console.log(body)
    })
}

module.exports.server_check = server_check;
module.exports.validation = validation;
