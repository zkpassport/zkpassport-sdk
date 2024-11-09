"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EU_COUNTRIES = exports.SANCTIONED_COUNTRIES = void 0;
/**
 * List of countries that are sanctioned by the US government.
 */
exports.SANCTIONED_COUNTRIES = [
    "North Korea",
    "Iran",
    "Iraq",
    "Libya",
    "Somalia",
    "Sudan",
    "Syrian Arab Republic",
    "Yemen",
];
exports.EU_COUNTRIES = [
    "Austria",
    "Belgium",
    "Bulgaria",
    "Croatia",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Estonia",
    "Finland",
    "France",
    "Germany",
    "Greece",
    "Hungary",
    "Ireland",
    "Italy",
    "Latvia",
    "Lithuania",
    "Luxembourg",
    "Malta",
    "Netherlands",
    "Poland",
    "Portugal",
    "Romania",
    "Slovakia",
    "Slovenia",
    "Spain",
    "Sweden",
];
var constants = {
    countries: {
        EU: exports.EU_COUNTRIES,
        SANCTIONED: exports.SANCTIONED_COUNTRIES,
    },
};
exports.default = constants;
