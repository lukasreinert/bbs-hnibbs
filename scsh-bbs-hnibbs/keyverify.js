var CVC = require("scsh/eac/CVC").CVC;

var FileInputStream = java.io.FileInputStream;
var File = java.io.File;
var importDir = new File("key_attestation");
assert(importDir.exists(), "Import directory not found");

function loadDER(filename) {
    var file = new File(importDir, filename);
    var fis = new FileInputStream(file);

    var data = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, fis.available());
    fis.read(data);
    fis.close();

    return new ByteString(data, HEX);
}

// Helper function to convert DER bytes to CVC object
function loadCVC(derBytes) {
    return new CVC(derBytes);
}

// Load the chain
var srca = loadCVC(loadDER("srca.der"));
var dica = loadCVC(loadDER("dica.der"));
var devicecert = loadCVC(loadDER("device.der"));
var att = loadCVC(loadDER("attestation-request.der"));

// Verify the chain
var crypto = new Crypto();
assert(dica.verifyWithCVC(crypto, srca), "DICA verification failed");
assert(devicecert.verifyWithCVC(crypto, dica), "Device certificate verification failed");
assert(att.verifyATWithCVC(crypto, devicecert), "Attestation request verification failed");

print("Certificate chain and attestation request verified!");
