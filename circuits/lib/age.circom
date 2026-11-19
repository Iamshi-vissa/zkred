pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// AgeAtLeast(minYears): proves currentDate - birthDate >= minYears * 10000,
// with both dates encoded as YYYYMMDD integers (e.g. 20080229).
//
// Why YYYYMMDD: with d = 10000*dYears + (MMDD_now - MMDD_birth) and
// |MMDD_now - MMDD_birth| < 10000, "d >= 180000" holds exactly when the
// 18th birthday has been reached on the calendar - leap years included,
// with no division or calendar logic inside the circuit.
//
// Dates are NOT checked to be real calendar dates here: birthDate is fixed by
// the issuer inside the leaf, and currentDate is checked by the contract
// against block.timestamp. The circuit only needs them to be small integers.
template AgeAtLeast(minYears) {
    signal input birthDate;
    signal input currentDate;

    // [C6] Range checks: both dates must fit in 32 bits.
    // The comparator below is only sound for inputs below 2^n. Without these,
    // field arithmetic wraps: e.g. birthDate = r - 1 ("negative one") makes
    // currentDate - birthDate look like a huge positive age.
    // YYYYMMDD <= 99991231 < 2^27, so 32 bits never rejects a real date.
    component birthBits = Num2Bits(32);
    birthBits.in <== birthDate;
    component currentBits = Num2Bits(32);
    currentBits.in <== currentDate;

    // [C7] currentDate >= birthDate + minYears*10000.
    // Compared with n = 33 bits: birthDate + 180000 < 2^32 + 2^18 < 2^33, so
    // both comparator inputs are guaranteed in range by C6.
    // The output must be CONSTRAINED to 1 (===), not merely computed: lab 01
    // shows what happens when the result is only assigned with <--.
    component geq = GreaterEqThan(33);
    geq.in[0] <== currentDate;
    geq.in[1] <== birthDate + minYears * 10000;
    geq.out === 1;
}
