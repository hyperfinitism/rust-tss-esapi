// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    Error, WrapperErrorKind,
    constants::tss::{
        TPM2_EO_BITCLEAR, TPM2_EO_BITSET, TPM2_EO_EQ, TPM2_EO_NEQ, TPM2_EO_SIGNED_GE,
        TPM2_EO_SIGNED_GT, TPM2_EO_SIGNED_LE, TPM2_EO_SIGNED_LT, TPM2_EO_UNSIGNED_GE,
        TPM2_EO_UNSIGNED_GT, TPM2_EO_UNSIGNED_LE, TPM2_EO_UNSIGNED_LT,
    },
    interface_types::ArithmeticComparison,
    tss2_esys::TPM2_EO,
};

#[test]
fn test_conversions() {
    let expected_values = [
        (ArithmeticComparison::Eq, TPM2_EO_EQ),
        (ArithmeticComparison::Neq, TPM2_EO_NEQ),
        (ArithmeticComparison::SignedGt, TPM2_EO_SIGNED_GT),
        (ArithmeticComparison::UnsignedGt, TPM2_EO_UNSIGNED_GT),
        (ArithmeticComparison::SignedLt, TPM2_EO_SIGNED_LT),
        (ArithmeticComparison::UnsignedLt, TPM2_EO_UNSIGNED_LT),
        (ArithmeticComparison::SignedGe, TPM2_EO_SIGNED_GE),
        (ArithmeticComparison::UnsignedGe, TPM2_EO_UNSIGNED_GE),
        (ArithmeticComparison::SignedLe, TPM2_EO_SIGNED_LE),
        (ArithmeticComparison::UnsignedLe, TPM2_EO_UNSIGNED_LE),
        (ArithmeticComparison::BitSet, TPM2_EO_BITSET),
        (ArithmeticComparison::BitClear, TPM2_EO_BITCLEAR),
    ];

    for (comparison, raw_value) in expected_values {
        assert_eq!(raw_value, TPM2_EO::from(comparison));
        assert_eq!(
            comparison,
            ArithmeticComparison::try_from(raw_value).unwrap()
        );
    }
}

#[test]
fn test_invalid_conversion() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        ArithmeticComparison::try_from(TPM2_EO::MAX),
    );
}
