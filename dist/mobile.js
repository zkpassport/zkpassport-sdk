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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZkPassportProver = void 0;
var utils_1 = require("@noble/ciphers/utils");
var websocket_1 = require("./websocket");
var json_rpc_1 = require("./json-rpc");
var encryption_1 = require("./encryption");
var logger_1 = __importDefault(require("./logger"));
var ZkPassportProver = /** @class */ (function () {
    function ZkPassportProver() {
        this.topicToKeyPair = {};
        this.topicToWebSocketClient = {};
        this.topicToRemoteDomainVerified = {};
        this.topicToSharedSecret = {};
        this.topicToRemotePublicKey = {};
        this.onDomainVerifiedCallbacks = {};
        this.onBridgeConnectCallbacks = {};
        this.onWebsiteDomainVerifyFailureCallbacks = {};
    }
    /**
     * @notice Handle an encrypted message.
     * @param request The request.
     * @param outerRequest The outer request.
     */
    ZkPassportProver.prototype.handleEncryptedMessage = function (topic, request, outerRequest) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        logger_1.default.debug('Received encrypted message:', request);
                        if (!(request.method === 'hello')) return [3 /*break*/, 2];
                        logger_1.default.info("Successfully verified origin domain name: ".concat(outerRequest.origin));
                        this.topicToRemoteDomainVerified[topic] = true;
                        return [4 /*yield*/, Promise.all(this.onDomainVerifiedCallbacks[topic].map(function (callback) { return callback(); }))];
                    case 1:
                        _a.sent();
                        return [3 /*break*/, 3];
                    case 2:
                        if (request.method === 'closed_page') {
                            // TODO: Implement
                        }
                        _a.label = 3;
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @notice Scan a credentirequest QR code.
     * @returns
     */
    ZkPassportProver.prototype.scan = function (url_1) {
        return __awaiter(this, arguments, void 0, function (url, _a) {
            var parsedUrl, domain, topic, pubkeyHex, pubkey, keyPair, _b, _c, _d, wsClient;
            var _this = this;
            var _e = _a === void 0 ? {} : _a, keyPairOverride = _e.keyPairOverride;
            return __generator(this, function (_f) {
                switch (_f.label) {
                    case 0:
                        parsedUrl = new URL(url);
                        domain = parsedUrl.searchParams.get('d');
                        topic = parsedUrl.searchParams.get('t');
                        pubkeyHex = parsedUrl.searchParams.get('p');
                        if (!domain || !topic || !pubkeyHex) {
                            throw new Error('Invalid URL: missing required parameters');
                        }
                        pubkey = new Uint8Array(Buffer.from(pubkeyHex, 'hex'));
                        this.domain = domain;
                        _b = keyPairOverride;
                        if (_b) return [3 /*break*/, 2];
                        return [4 /*yield*/, (0, encryption_1.generateECDHKeyPair)()];
                    case 1:
                        _b = (_f.sent());
                        _f.label = 2;
                    case 2:
                        keyPair = _b;
                        this.topicToKeyPair[topic] = {
                            privateKey: keyPair.privateKey,
                            publicKey: keyPair.publicKey,
                        };
                        this.topicToRemotePublicKey[topic] = pubkey;
                        _c = this.topicToSharedSecret;
                        _d = topic;
                        return [4 /*yield*/, (0, encryption_1.getSharedSecret)((0, utils_1.bytesToHex)(keyPair.privateKey), (0, utils_1.bytesToHex)(pubkey))];
                    case 3:
                        _c[_d] = _f.sent();
                        this.topicToRemoteDomainVerified[topic] = false;
                        this.onDomainVerifiedCallbacks[topic] = [];
                        this.onBridgeConnectCallbacks[topic] = [];
                        wsClient = (0, websocket_1.getWebSocketClient)("wss://bridge.zkpassport.id?topic=".concat(topic, "&pubkey=").concat((0, utils_1.bytesToHex)(keyPair.publicKey)));
                        this.topicToWebSocketClient[topic] = wsClient;
                        wsClient.onopen = function () { return __awaiter(_this, void 0, void 0, function () {
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0:
                                        logger_1.default.info('[mobile] WebSocket connection established');
                                        return [4 /*yield*/, Promise.all(this.onBridgeConnectCallbacks[topic].map(function (callback) { return callback(); }))
                                            // Server sends handshake automatically (when it sees a pubkey in websocket URI)
                                            // wsClient.send(
                                            //   JSON.stringify(
                                            //     createJsonRpcRequest('handshake', {
                                            //       pubkey: bytesToHex(keyPair.publicKey),
                                            //     }),
                                            //   ),
                                            // )
                                        ];
                                    case 1:
                                        _a.sent();
                                        return [2 /*return*/];
                                }
                            });
                        }); };
                        wsClient.addEventListener('message', function (event) { return __awaiter(_this, void 0, void 0, function () {
                            var data, originDomain, payload, decrypted, decryptedJson, error_1, error_2;
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0:
                                        logger_1.default.info('[mobile] Received message:', event.data);
                                        _a.label = 1;
                                    case 1:
                                        _a.trys.push([1, 7, , 8]);
                                        data = JSON.parse(event.data);
                                        originDomain = data.origin ? new URL(data.origin).hostname : undefined;
                                        // Origin domain must match domain in QR code
                                        if (originDomain !== this.domain) {
                                            logger_1.default.warn("[mobile] Origin does not match domain in QR code. Expected ".concat(this.domain, " but got ").concat(originDomain));
                                            return [2 /*return*/];
                                        }
                                        if (!(data.method === 'encryptedMessage')) return [3 /*break*/, 6];
                                        payload = new Uint8Array(atob(data.params.payload)
                                            .split('')
                                            .map(function (c) { return c.charCodeAt(0); }));
                                        _a.label = 2;
                                    case 2:
                                        _a.trys.push([2, 5, , 6]);
                                        return [4 /*yield*/, (0, encryption_1.decrypt)(payload, this.topicToSharedSecret[topic], topic)];
                                    case 3:
                                        decrypted = _a.sent();
                                        decryptedJson = JSON.parse(decrypted);
                                        return [4 /*yield*/, this.handleEncryptedMessage(topic, decryptedJson, data)];
                                    case 4:
                                        _a.sent();
                                        return [3 /*break*/, 6];
                                    case 5:
                                        error_1 = _a.sent();
                                        logger_1.default.error('[mobile] Error decrypting message:', error_1);
                                        return [3 /*break*/, 6];
                                    case 6: return [3 /*break*/, 8];
                                    case 7:
                                        error_2 = _a.sent();
                                        logger_1.default.error('[mobile] Error:', error_2);
                                        return [3 /*break*/, 8];
                                    case 8: return [2 /*return*/];
                                }
                            });
                        }); });
                        wsClient.onerror = function (error) {
                            logger_1.default.error('[mobile] WebSocket error:', error);
                        };
                        return [2 /*return*/, {
                                domain: this.domain,
                                requestId: topic,
                                isBridgeConnected: function () { return _this.topicToWebSocketClient[topic].readyState === WebSocket.OPEN; },
                                isDomainVerified: function () { return _this.topicToRemoteDomainVerified[topic] === true; },
                                onDomainVerified: function (callback) { return _this.onDomainVerifiedCallbacks[topic].push(callback); },
                                onBridgeConnect: function (callback) { return _this.onBridgeConnectCallbacks[topic].push(callback); },
                                notifyReject: function () { return __awaiter(_this, void 0, void 0, function () {
                                    return __generator(this, function (_a) {
                                        switch (_a.label) {
                                            case 0: return [4 /*yield*/, (0, json_rpc_1.sendEncryptedJsonRpcRequest)('reject', null, this.topicToSharedSecret[topic], topic, this.topicToWebSocketClient[topic])];
                                            case 1:
                                                _a.sent();
                                                return [2 /*return*/];
                                        }
                                    });
                                }); },
                                notifyAccept: function () { return __awaiter(_this, void 0, void 0, function () {
                                    return __generator(this, function (_a) {
                                        switch (_a.label) {
                                            case 0: return [4 /*yield*/, (0, json_rpc_1.sendEncryptedJsonRpcRequest)('accept', null, this.topicToSharedSecret[topic], topic, this.topicToWebSocketClient[topic])];
                                            case 1:
                                                _a.sent();
                                                return [2 /*return*/];
                                        }
                                    });
                                }); },
                                notifyDone: function (proof) { return __awaiter(_this, void 0, void 0, function () {
                                    return __generator(this, function (_a) {
                                        switch (_a.label) {
                                            case 0: return [4 /*yield*/, (0, json_rpc_1.sendEncryptedJsonRpcRequest)('done', { proof: proof }, this.topicToSharedSecret[topic], topic, this.topicToWebSocketClient[topic])];
                                            case 1:
                                                _a.sent();
                                                return [2 /*return*/];
                                        }
                                    });
                                }); },
                                notifyError: function (error) { return __awaiter(_this, void 0, void 0, function () {
                                    return __generator(this, function (_a) {
                                        switch (_a.label) {
                                            case 0: return [4 /*yield*/, (0, json_rpc_1.sendEncryptedJsonRpcRequest)('error', { error: error }, this.topicToSharedSecret[topic], topic, this.topicToWebSocketClient[topic])];
                                            case 1:
                                                _a.sent();
                                                return [2 /*return*/];
                                        }
                                    });
                                }); },
                            }];
                }
            });
        });
    };
    return ZkPassportProver;
}());
exports.ZkPassportProver = ZkPassportProver;
/*want to check "TUR" is not in the list

find some j where countries[j] < TUR < countries[j+1]

With each letter converted to its ASCII value and the three letters forming a 24 bit number.

Example:
TUR -> 84 117 114 -> 0x54 0x75 0x72 -> 0x547572 -> 5,535,090
*/
