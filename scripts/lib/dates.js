// YYYYMMDD date helpers (UTC). Mirrors circuits/lib/age.circom.
//
// A YYYYMMDD integer d = 10000*Y + 100*M + D. For two dates,
//   now - birth = 10000*(dY) + (MMDD_now - MMDD_birth), |MMDD diff| < 10000,
// so "now - birth >= 180000" is exactly "the 18th birthday has passed".
// Someone born 29 Feb is treated as turning 18 on 1 Mar in non-leap years.

const MAX_YEAR = 9999;

function daysInMonth(y, m) {
  return new Date(Date.UTC(y, m, 0)).getUTCDate(); // m is 1-based here
}

/** True if `n` is an integer YYYYMMDD naming a real calendar date. */
export function isValidYYYYMMDD(n) {
  if (!Number.isSafeInteger(n) || n < 10101 || n > 99991231) return false;
  const y = Math.floor(n / 10000);
  const m = Math.floor(n / 100) % 100;
  const d = n % 100;
  return y >= 1 && y <= MAX_YEAR && m >= 1 && m <= 12 && d >= 1 && d <= daysInMonth(y, m);
}

/** Date (or ms timestamp) -> YYYYMMDD in UTC. */
export function toYYYYMMDD(date) {
  const dt = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(dt.getTime())) throw new RangeError("invalid date");
  return dt.getUTCFullYear() * 10000 + (dt.getUTCMonth() + 1) * 100 + dt.getUTCDate();
}

/** Unix seconds (e.g. block.timestamp) -> YYYYMMDD in UTC. */
export function timestampToYYYYMMDD(seconds) {
  return toYYYYMMDD(Number(seconds) * 1000);
}

/** Reference implementation of the circuit's age rule. */
export function isAtLeastAge(birthDate, currentDate, years = 18) {
  for (const [name, v] of [["birthDate", birthDate], ["currentDate", currentDate]]) {
    if (!isValidYYYYMMDD(v)) throw new RangeError(`${name} ${v} is not a valid YYYYMMDD date`);
  }
  return currentDate - birthDate >= years * 10000;
}
