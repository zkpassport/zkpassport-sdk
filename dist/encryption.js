"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateECDHKeyPair = generateECDHKeyPair;
exports.getSharedSecret = getSharedSecret;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
var aes_1 = require("@noble/ciphers/aes");
var utils_1 = require("@noble/ciphers/utils");
function sha256Truncate(topic) {
    return __awaiter(this, void 0, void 0, function () {
        var encoder, data, hashBuffer, fullHashArray, truncatedHashArray;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    encoder = new TextEncoder();
                    data = encoder.encode(topic);
                    return [4 /*yield*/, crypto.subtle.digest('SHA-256', data)];
                case 1:
                    hashBuffer = _a.sent();
                    fullHashArray = new Uint8Array(hashBuffer);
                    truncatedHashArray = fullHashArray.slice(0, 12);
                    return [2 /*return*/, truncatedHashArray];
            }
        });
    });
}
function generateECDHKeyPair() {
    return __awaiter(this, void 0, void 0, function () {
        var secp256k1, privKey, pubKey;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, import('@noble/secp256k1')];
                case 1:
                    secp256k1 = _a.sent();
                    privKey = secp256k1.utils.randomPrivateKey();
                    pubKey = secp256k1.getPublicKey(privKey);
                    return [2 /*return*/, {
                            privateKey: privKey,
                            publicKey: pubKey,
                        }];
            }
        });
    });
}
function getSharedSecret(privateKey, publicKey) {
    return __awaiter(this, void 0, void 0, function () {
        var secp256k1, sharedSecret;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, import('@noble/secp256k1')];
                case 1:
                    secp256k1 = _a.sent();
                    sharedSecret = secp256k1.getSharedSecret(privateKey, publicKey);
                    return [2 /*return*/, sharedSecret.slice(0, 32)];
            }
        });
    });
}
function encrypt(message, sharedSecret, topic) {
    return __awaiter(this, void 0, void 0, function () {
        var nonce, aes, data, ciphertext;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, sha256Truncate(topic)];
                case 1:
                    nonce = _a.sent();
                    aes = (0, aes_1.gcm)(sharedSecret, nonce);
                    data = (0, utils_1.utf8ToBytes)(message);
                    ciphertext = aes.encrypt(data);
                    return [2 /*return*/, ciphertext];
            }
        });
    });
}
function decrypt(ciphertext, sharedSecret, topic) {
    return __awaiter(this, void 0, void 0, function () {
        var nonce, aes, data, dataString;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, sha256Truncate(topic)];
                case 1:
                    nonce = _a.sent();
                    aes = (0, aes_1.gcm)(sharedSecret, nonce);
                    data = aes.decrypt(ciphertext);
                    dataString = new TextDecoder().decode(data);
                    return [2 /*return*/, dataString];
            }
        });
    });
}
