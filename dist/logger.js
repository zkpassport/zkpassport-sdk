"use strict";
// import { createLogger, transports, format } from 'winston'
// import colors from 'colors/safe'
// import util from 'util'
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
// const logger = createLogger({
//   level: 'debug',
//   format: format.combine(
//     format.timestamp({ format: 'HH:mm' }),
//     format.printf(({ timestamp, level, message, additionalInfo }) => {
//       const colorMap = {
//         debug: colors.cyan,
//         info: colors.green,
//         warn: colors.yellow,
//         error: colors.red,
//       } as const
//       const coloredLevel = (colorMap[level as keyof typeof colorMap] || colors.white)(level.toUpperCase())
//       let logMessage = `${timestamp} [${coloredLevel}] ${message}`
//       if (additionalInfo && additionalInfo.length > 0) {
//         logMessage += ' ' + util.inspect(additionalInfo, { depth: null, colors: true })
//       }
//       return logMessage
//     }),
//   ),
//   transports: [new transports.Console()],
// })
// const customLogger = {
//   debug: (message: string, ...args: any[]) => logger.debug(message, { additionalInfo: args }),
//   info: (message: string, ...args: any[]) => logger.info(message, { additionalInfo: args }),
//   warn: (message: string, ...args: any[]) => logger.warn(message, { additionalInfo: args }),
//   error: (message: string, ...args: any[]) => logger.error(message, { additionalInfo: args }),
// }
var customLogger = {
    debug: function (message) {
        var args = [];
        for (var _i = 1; _i < arguments.length; _i++) {
            args[_i - 1] = arguments[_i];
        }
        return console.debug.apply(console, __spreadArray([message], args, false));
    },
    info: function (message) {
        var args = [];
        for (var _i = 1; _i < arguments.length; _i++) {
            args[_i - 1] = arguments[_i];
        }
        return console.info.apply(console, __spreadArray([message], args, false));
    },
    warn: function (message) {
        var args = [];
        for (var _i = 1; _i < arguments.length; _i++) {
            args[_i - 1] = arguments[_i];
        }
        return console.warn.apply(console, __spreadArray([message], args, false));
    },
    error: function (message) {
        var args = [];
        for (var _i = 1; _i < arguments.length; _i++) {
            args[_i - 1] = arguments[_i];
        }
        return console.error.apply(console, __spreadArray([message], args, false));
    },
};
exports.default = customLogger;
