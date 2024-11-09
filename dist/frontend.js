"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZkPassport = exports.constants = void 0;
var crypto_1 = require("crypto");
var utils_1 = require("@noble/ciphers/utils");
var websocket_1 = require("./websocket");
var json_rpc_1 = require("./json-rpc");
var encryption_1 = require("./encryption");
var constants_1 = __importDefault(require("./constants"));
exports.constants = constants_1.default;
var logger_1 = __importDefault(require("./logger"));
function numericalCompare(fnName, key, value, requestId, requestIdToConfig) {
    var _a;
    requestIdToConfig[requestId][key] = __assign(__assign({}, requestIdToConfig[requestId][key]), (_a = {}, _a[fnName] = value, _a));
}
function rangeCompare(key, value, requestId, requestIdToConfig) {
    requestIdToConfig[requestId][key] = __assign(__assign({}, requestIdToConfig[requestId][key]), { range: value });
}
function generalCompare(fnName, key, value, requestId, requestIdToConfig) {
    var _a;
    requestIdToConfig[requestId][key] = __assign(__assign({}, requestIdToConfig[requestId][key]), (_a = {}, _a[fnName] = value, _a));
}
var ZkPassport = /** @class */ (function () {
    function ZkPassport(_domain) {
        this.topicToConfig = {};
        this.topicToKeyPair = {};
        this.topicToWebSocketClient = {};
        this.topicToSharedSecret = {};
        this.topicToQRCodeScanned = {};
        this.onQRCodeScannedCallbacks = {};
        this.onGeneratingProofCallbacks = {};
        this.onBridgeConnectCallbacks = {};
        this.onProofGeneratedCallbacks = {};
        this.onRejectCallbacks = {};
        this.onErrorCallbacks = {};
        this.topicToService = {};
        if (!_domain && typeof window === 'undefined') {
            throw new Error('Domain argument is required in Node.js environment');
        }
        this.domain = _domain || window.location.hostname;
    }
    /**
     * @notice Handle an encrypted message.
     * @param request The request.
     * @param outerRequest The outer request.
     */
    ZkPassport.prototype.handleEncryptedMessage = function (topic, request, outerRequest) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        logger_1.default.debug('Received encrypted message:', request);
                        if (!(request.method === 'accept')) return [3 /*break*/, 2];
                        logger_1.default.debug("User accepted the request and is generating a proof");
                        return [4 /*yield*/, Promise.all(this.onGeneratingProofCallbacks[topic].map(function (callback) { return callback(topic); }))];
                    case 1:
                        _a.sent();
                        return [3 /*break*/, 8];
                    case 2:
                        if (!(request.method === 'reject')) return [3 /*break*/, 4];
                        logger_1.default.debug("User rejected the request");
                        return [4 /*yield*/, Promise.all(this.onRejectCallbacks[topic].map(function (callback) { return callback(); }))];
                    case 3:
                        _a.sent();
                        return [3 /*break*/, 8];
                    case 4:
                        if (!(request.method === 'done')) return [3 /*break*/, 6];
                        logger_1.default.debug("User generated proof");
                        return [4 /*yield*/, Promise.all(this.onProofGeneratedCallbacks[topic].map(function (callback) { return callback(request.params.result); }))];
                    case 5:
                        _a.sent();
                        return [3 /*break*/, 8];
                    case 6:
                        if (!(request.method === 'error')) return [3 /*break*/, 8];
                        return [4 /*yield*/, Promise.all(this.onErrorCallbacks[topic].map(function (callback) { return callback(request.params.error); }))];
                    case 7:
                        _a.sent();
                        _a.label = 8;
                    case 8: return [2 /*return*/];
                }
            });
        });
    };
    ZkPassport.prototype.getZkPassportRequest = function (topic) {
        var _this = this;
        return {
            eq: function (key, value) {
                generalCompare('eq', key, value, topic, _this.topicToConfig);
                return _this.getZkPassportRequest(topic);
            },
            gte: function (key, value) {
                numericalCompare('gte', key, value, topic, _this.topicToConfig);
                return _this.getZkPassportRequest(topic);
            },
            gt: function (key, value) {
                numericalCompare('gt', key, value, topic, _this.topicToConfig);
                return _this.getZkPassportRequest(topic);
            },
            lte: function (key, value) {
                numericalCompare('lte', key, value, topic, _this.topicToConfig);
                return _this.getZkPassportRequest(topic);
            },
            lt: function (key, value) {
                numericalCompare('lt', key, value, topic, _this.topicToConfig);
                return _this.getZkPassportRequest(topic);
            },
            range: function (key, start, end) {
                rangeCompare(key, [start, end], topic, _this.topicToConfig);
                return _this.getZkPassportRequest(topic);
            },
            in: function (key, value) {
                generalCompare('in', key, value, topic, _this.topicToConfig);
                return _this.getZkPassportRequest(topic);
            },
            out: function (key, value) {
                generalCompare('out', key, value, topic, _this.topicToConfig);
                return _this.getZkPassportRequest(topic);
            },
            disclose: function (key) {
                _this.topicToConfig[topic][key] = __assign(__assign({}, _this.topicToConfig[topic][key]), { disclose: true });
                return _this.getZkPassportRequest(topic);
            },
            checkAML: function (country) {
                return _this.getZkPassportRequest(topic);
            },
            done: function () {
                var base64Config = Buffer.from(JSON.stringify(_this.topicToConfig[topic])).toString('base64');
                var base64Service = Buffer.from(JSON.stringify(_this.topicToService[topic])).toString('base64');
                var pubkey = (0, utils_1.bytesToHex)(_this.topicToKeyPair[topic].publicKey);
                return {
                    url: "https://zkpassport.id/r?d=".concat(_this.domain, "&t=").concat(topic, "&c=").concat(base64Config, "&s=").concat(base64Service, "&p=").concat(pubkey),
                    requestId: topic,
                    onQRCodeScanned: function (callback) { return _this.onQRCodeScannedCallbacks[topic].push(callback); },
                    onGeneratingProof: function (callback) { return _this.onGeneratingProofCallbacks[topic].push(callback); },
                    onBridgeConnect: function (callback) { return _this.onBridgeConnectCallbacks[topic].push(callback); },
                    onProofGenerated: function (callback) {
                        return _this.onProofGeneratedCallbacks[topic].push(callback);
                    },
                    onReject: function (callback) { return _this.onRejectCallbacks[topic].push(callback); },
                    onError: function (callback) { return _this.onErrorCallbacks[topic].push(callback); },
                    isBridgeConnected: function () { return _this.topicToWebSocketClient[topic].readyState === WebSocket.OPEN; },
                    isQRCodeScanned: function () { return _this.topicToQRCodeScanned[topic] === true; },
                };
            },
        };
    };
    /**
     * @notice Create a new request.
     * @returns The query builder object.
     */
    ZkPassport.prototype.request = function (_a) {
        return __awaiter(this, arguments, void 0, function (_b) {
            var topic, keyPair, _c, wsClient;
            var _this = this;
            var name = _b.name, logo = _b.logo, purpose = _b.purpose, topicOverride = _b.topicOverride, keyPairOverride = _b.keyPairOverride;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        topic = topicOverride || (0, crypto_1.randomBytes)(16).toString('hex');
                        _c = keyPairOverride;
                        if (_c) return [3 /*break*/, 2];
                        return [4 /*yield*/, (0, encryption_1.generateECDHKeyPair)()];
                    case 1:
                        _c = (_d.sent());
                        _d.label = 2;
                    case 2:
                        keyPair = _c;
                        this.topicToKeyPair[topic] = {
                            privateKey: keyPair.privateKey,
                            publicKey: keyPair.publicKey,
                        };
                        this.topicToConfig[topic] = {};
                        this.topicToService[topic] = { name: name, logo: logo, purpose: purpose };
                        this.onQRCodeScannedCallbacks[topic] = [];
                        this.onGeneratingProofCallbacks[topic] = [];
                        this.onBridgeConnectCallbacks[topic] = [];
                        this.onProofGeneratedCallbacks[topic] = [];
                        this.onRejectCallbacks[topic] = [];
                        this.onErrorCallbacks[topic] = [];
                        wsClient = (0, websocket_1.getWebSocketClient)("wss://bridge.zkpassport.id?topic=".concat(topic), this.domain);
                        this.topicToWebSocketClient[topic] = wsClient;
                        wsClient.onopen = function () { return __awaiter(_this, void 0, void 0, function () {
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0:
                                        logger_1.default.info('[frontend] WebSocket connection established');
                                        return [4 /*yield*/, Promise.all(this.onBridgeConnectCallbacks[topic].map(function (callback) { return callback(); }))];
                                    case 1:
                                        _a.sent();
                                        return [2 /*return*/];
                                }
                            });
                        }); };
                        wsClient.addEventListener('message', function (event) { return __awaiter(_this, void 0, void 0, function () {
                            var data, _a, _b, encryptedMessage, payload, decrypted, decryptedJson, error_1, error_2;
                            return __generator(this, function (_c) {
                                switch (_c.label) {
                                    case 0:
                                        logger_1.default.debug('[frontend] Received message:', event.data);
                                        _c.label = 1;
                                    case 1:
                                        _c.trys.push([1, 11, , 12]);
                                        data = JSON.parse(event.data);
                                        if (!(data.method === 'handshake')) return [3 /*break*/, 5];
                                        logger_1.default.debug('[frontend] Received handshake:', event.data);
                                        this.topicToQRCodeScanned[topic] = true;
                                        _a = this.topicToSharedSecret;
                                        _b = topic;
                                        return [4 /*yield*/, (0, encryption_1.getSharedSecret)((0, utils_1.bytesToHex)(keyPair.privateKey), data.params.pubkey)];
                                    case 2:
                                        _a[_b] = _c.sent();
                                        logger_1.default.debug('[frontend] Shared secret:', Buffer.from(this.topicToSharedSecret[topic]).toString('hex'));
                                        return [4 /*yield*/, (0, json_rpc_1.createEncryptedJsonRpcRequest)('hello', null, this.topicToSharedSecret[topic], topic)];
                                    case 3:
                                        encryptedMessage = _c.sent();
                                        logger_1.default.debug('[frontend] Sending encrypted message:', encryptedMessage);
                                        wsClient.send(JSON.stringify(encryptedMessage));
                                        return [4 /*yield*/, Promise.all(this.onQRCodeScannedCallbacks[topic].map(function (callback) { return callback(); }))];
                                    case 4:
                                        _c.sent();
                                        return [2 /*return*/];
                                    case 5:
                                        if (!(data.method === 'encryptedMessage')) return [3 /*break*/, 10];
                                        payload = new Uint8Array(atob(data.params.payload)
                                            .split('')
                                            .map(function (c) { return c.charCodeAt(0); }));
                                        _c.label = 6;
                                    case 6:
                                        _c.trys.push([6, 8, , 9]);
                                        return [4 /*yield*/, (0, encryption_1.decrypt)(payload, this.topicToSharedSecret[topic], topic)];
                                    case 7:
                                        decrypted = _c.sent();
                                        decryptedJson = JSON.parse(decrypted);
                                        this.handleEncryptedMessage(topic, decryptedJson, data);
                                        return [3 /*break*/, 9];
                                    case 8:
                                        error_1 = _c.sent();
                                        logger_1.default.error('[frontend] Error decrypting message:', error_1);
                                        return [3 /*break*/, 9];
                                    case 9: return [2 /*return*/];
                                    case 10: return [3 /*break*/, 12];
                                    case 11:
                                        error_2 = _c.sent();
                                        logger_1.default.error('[frontend] Error:', error_2);
                                        return [3 /*break*/, 12];
                                    case 12: return [2 /*return*/];
                                }
                            });
                        }); });
                        wsClient.onerror = function (error) {
                            logger_1.default.error('[frontend] WebSocket error:', error);
                        };
                        return [2 /*return*/, this.getZkPassportRequest(topic)];
                }
            });
        });
    };
    /**
     * @notice Verifies a proof.
     * @param proof The proof to verify.
     * @returns True if the proof is valid, false otherwise.
     */
    ZkPassport.prototype.verify = function (result) {
        // const backend = new UltraHonkBackend(proofOfAgeCircuit as CompiledCircuit)
        // const proofData: ProofData = {
        //   proof: Buffer.from(result.proof as string, 'hex'),
        //   // TODO: extract the public inputs from the proof
        //   publicInputs: [],
        // }
        // return backend.verifyProof(proofData)
    };
    /**
     * @notice Returns the URL of the request.
     * @param requestId The request ID.
     * @returns The URL of the request.
     */
    ZkPassport.prototype.getUrl = function (requestId) {
        var pubkey = (0, utils_1.bytesToHex)(this.topicToKeyPair[requestId].publicKey);
        var base64Config = Buffer.from(JSON.stringify(this.topicToConfig[requestId])).toString('base64');
        var base64Service = Buffer.from(JSON.stringify(this.topicToService[requestId])).toString('base64');
        return "https://zkpassport.id/r?d=".concat(this.domain, "&t=").concat(requestId, "&c=").concat(base64Config, "&s=").concat(base64Service, "&p=").concat(pubkey);
    };
    /**
     * @notice Cancels a request by closing the WebSocket connection and deleting the associated data.
     * @param requestId The request ID.
     */
    ZkPassport.prototype.cancelRequest = function (requestId) {
        this.topicToWebSocketClient[requestId].close();
        delete this.topicToWebSocketClient[requestId];
        delete this.topicToKeyPair[requestId];
        delete this.topicToConfig[requestId];
        delete this.topicToSharedSecret[requestId];
        this.onQRCodeScannedCallbacks[requestId] = [];
        this.onGeneratingProofCallbacks[requestId] = [];
        this.onBridgeConnectCallbacks[requestId] = [];
        this.onProofGeneratedCallbacks[requestId] = [];
        this.onRejectCallbacks[requestId] = [];
        this.onErrorCallbacks[requestId] = [];
    };
    return ZkPassport;
}());
exports.ZkPassport = ZkPassport;
/*want to check "TUR" is not in the list

find some j where countries[j] < TUR < countries[j+1]

With each letter converted to its ASCII value and the three letters forming a 24 bit number.

Example:
TUR -> 84 117 114
*/
