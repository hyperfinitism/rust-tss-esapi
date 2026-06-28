// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    Error, WrapperErrorKind,
    constants::{AttachedComponentCapability, tss::TPM_AT_VEND},
    structures::AttachedComponentOutput,
    tss2_esys::TPMS_AC_OUTPUT,
};

#[test]
fn test_conversions() {
    let expected_tag = AttachedComponentCapability::PairingValue1;
    let expected_data = 0xaabb_ccdd;

    let expected_tpms_ac_output = TPMS_AC_OUTPUT {
        tag: expected_tag.into(),
        data: expected_data,
    };

    let output = AttachedComponentOutput::try_from(expected_tpms_ac_output)
        .expect("Failed to convert TPMS_AC_OUTPUT");

    assert_eq!(
        output.tag(),
        expected_tag,
        "Converted AttachedComponentOutput did not contain the expected tag",
    );
    assert_eq!(
        output.data(),
        expected_data,
        "Converted AttachedComponentOutput did not contain the expected data",
    );

    let actual_tpms_ac_output: TPMS_AC_OUTPUT = output.into();

    assert_eq!(expected_tpms_ac_output.tag, actual_tpms_ac_output.tag);
    assert_eq!(expected_tpms_ac_output.data, actual_tpms_ac_output.data);
}

#[test]
fn test_vendor_specific_conversion() {
    let expected_tag = AttachedComponentCapability::new_vendor_specific(TPM_AT_VEND)
        .expect("Failed to create vendor-specific TPM_AT");
    let tss_tag: tss_esapi::tss2_esys::TPM_AT = expected_tag.into();

    assert_eq!(
        AttachedComponentCapability::try_from(tss_tag)
            .expect("Failed to convert vendor-specific TPM_AT"),
        expected_tag,
    );
}

#[test]
fn test_invalid_conversions() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        AttachedComponentCapability::try_from(3),
        "Converting an undefined TPM_AT value did not produce the expected error",
    );

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        AttachedComponentCapability::new_vendor_specific(TPM_AT_VEND - 1),
        "Creating a vendor-specific TPM_AT below TPM_AT_VEND did not produce the expected error",
    );

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        AttachedComponentOutput::try_from(TPMS_AC_OUTPUT { tag: 3, data: 0 }),
        "Converting TPMS_AC_OUTPUT with an invalid tag did not produce the expected error",
    );
}
