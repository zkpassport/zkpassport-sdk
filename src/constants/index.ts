import { CountryName } from '../types/countries'

/**
 * List of countries that are sanctioned by the US government.
 */
export const SANCTIONED_COUNTRIES: CountryName[] = [
  'North Korea',
  'Iran',
  'Iraq',
  'Libya',
  'Somalia',
  'Sudan',
  'Syrian Arab Republic',
  'Yemen',
]

export const EU_COUNTRIES: CountryName[] = [
  'Austria',
  'Belgium',
  'Bulgaria',
  'Croatia',
  'Cyprus',
  'Czech Republic',
  'Denmark',
  'Estonia',
  'Finland',
  'France',
  'Germany',
  'Greece',
  'Hungary',
  'Ireland',
  'Italy',
  'Latvia',
  'Lithuania',
  'Luxembourg',
  'Malta',
  'Netherlands',
  'Poland',
  'Portugal',
  'Romania',
  'Slovakia',
  'Slovenia',
  'Spain',
  'Sweden',
]

export const EEA_COUNTRIES: CountryName[] = [...EU_COUNTRIES, 'Iceland', 'Liechtenstein', 'Norway']

export const SCHENGEN_COUNTRIES: CountryName[] = [
  ...EU_COUNTRIES.filter((country) => country !== 'Cyprus' && country !== 'Ireland'),
  'Switzerland',
  'Iceland',
  'Liechtenstein',
  'Norway',
]

export const ASEAN_COUNTRIES: CountryName[] = [
  'Brunei Darussalam',
  'Cambodia',
  'Indonesia',
  "Lao People's Democratic Republic",
  'Malaysia',
  'Myanmar',
  'Philippines',
  'Singapore',
  'Thailand',
  'Vietnam',
]

export const MERCOSUR_COUNTRIES: CountryName[] = [
  'Argentina',
  'Brazil',
  'Chile',
  'Colombia',
  'Paraguay',
  'Uruguay',
]

const constants = {
  countries: {
    EU: EU_COUNTRIES,
    EEA: EEA_COUNTRIES,
    SCHENGEN: SCHENGEN_COUNTRIES,
    SANCTIONED: SANCTIONED_COUNTRIES,
    MERCOSUR: MERCOSUR_COUNTRIES,
    ASEAN: ASEAN_COUNTRIES,
  },
}

export default constants
