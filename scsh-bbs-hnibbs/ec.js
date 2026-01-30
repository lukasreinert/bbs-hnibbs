/**
 * SmartCard-HSM Script
 *
 * Inspired by example scripts from CardContact Software & System Consulting
 * (Andreas Schwier, www.cardcontact.de), but fully implemented by [Your Name].
 */

var FileOutputStream = java.io.FileOutputStream;
var File = java.io.File;
var exportDir = new File("key_attestation");
if (!exportDir.exists()) {
    exportDir.mkdir();
}

function saveDER(filename, bytes) {
    var f = new FileOutputStream(new File(exportDir, filename));
    for (var i = 0; i < bytes.length; i++) {
        f.write(bytes.byteAt(i));
    }
    f.close();
}

function savePEM(filename, label, bytes) {
    var b64 = bytes.toString(BASE64);
    var pem = "-----BEGIN " + label + "-----\n" + b64.replace(/(.{64})/g, "$1\n") + "\n-----END " + label + "-----\n";

    var f = new FileOutputStream(new File(exportDir, filename));
    f.write(new java.lang.String(pem).getBytes());
    f.close();
}

var SmartCardHSM = require("scsh/sc-hsm/SmartCardHSM").SmartCardHSM;
var SmartCardHSMKeySpecGenerator = require("scsh/sc-hsm/SmartCardHSM").SmartCardHSMKeySpecGenerator;
var HSMKeyStore = require("scsh/sc-hsm/HSMKeyStore").HSMKeyStore;

var crypto = new Crypto();

// Create card access object
var card = new Card(_scsh3.reader);

// Create SmartCard-HSM card service
var sc = new SmartCardHSM(card);

// Attach key store
var ks = new HSMKeyStore(sc);

// Read device certificate and validate chain up to the SRCA
var devAutCert = sc.readBinary(SmartCardHSM.C_DevAut);
var chain = SmartCardHSM.validateCertificateChain(crypto, devAutCert);
if (this.chain == null) {
    throw new GPError(module.id, GPError.DEVICE_ERROR, 0, "SmartCard-HSM authentication failed");
}

// Login
sc.verifyUserPIN(new ByteString(UserPIN, ASCII));

// Regenerate key if exists
if (ks.hasKey(LABEL)) {
    ks.deleteKey(LABEL);
}

var key = new Key();
key.setComponent(Key.ECC_CURVE_OID, new ByteString(CURVE, OID));
var spec = new SmartCardHSMKeySpecGenerator(Crypto.EC, key);
if (KUC > 0) {
    spec.setKeyUseCounter(KUC);
}

var req = ks.generateKeyPair(LABEL, spec);
ks.storeEndEntityCertificate(LABEL, req);

var reqBytes = req.getBytes();

assert(chain.dica.verifyWithCVC(crypto, chain.srca), "Could not validate DICA");
assert(chain.devicecert.verifyWithCVC(crypto, chain.dica), "Could not validate Device");
assert(req.verifyATWithCVC(crypto, chain.devicecert), "Could not validate request");

// Export certificate chain
savePEM("srca.pem", "CVCERTIFICATE", chain.srca.getBytes());
saveDER("srca.der", chain.srca.getBytes());

savePEM("dica.pem", "CVCERTIFICATE", chain.dica.getBytes());
saveDER("dica.der", chain.dica.getBytes());

savePEM("device.pem", "CVCERTIFICATE", chain.devicecert.getBytes());
saveDER("device.der", chain.devicecert.getBytes());

req.decorate();

savePEM("attestation-request.pem", "ATTESTATIONREQUEST", reqBytes);
saveDER("attestation-request.der", reqBytes);
