// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    Error, WrapperErrorKind,
    constants::AttachedComponentCapability,
    structures::{AttachedComponentCapabilities, AttachedComponentOutput},
    tss2_esys::{TPML_AC_CAPABILITIES, TPMS_AC_OUTPUT},
};

#[test]
fn test_valid_conversions() {
    let expected_outputs = vec![
        AttachedComponentOutput::new(AttachedComponentCapability::Any, 10),
        AttachedComponentOutput::new(AttachedComponentCapability::Error, 20),
        AttachedComponentOutput::new(AttachedComponentCapability::PairingValue1, 30),
    ];

    let expected_tpml_ac_capabilities: TPML_AC_CAPABILITIES =
        expected_outputs
            .iter()
            .fold(Default::default(), |mut acc, v| {
                acc.acCapabilities[acc.count as usize] = TPMS_AC_OUTPUT::from(*v);
                acc.count += 1;
                acc
            });

    let capabilities_from_vec: AttachedComponentCapabilities =
        expected_outputs.clone().try_into().expect(
            "Failed to convert Vec<AttachedComponentOutput> into AttachedComponentCapabilities",
        );

    assert_eq!(expected_outputs.len(), capabilities_from_vec.len());
    expected_outputs
        .iter()
        .zip(capabilities_from_vec.as_ref())
        .for_each(|(expected, actual)| assert_eq!(expected, actual));

    let capabilities_from_tss: AttachedComponentCapabilities = expected_tpml_ac_capabilities
        .try_into()
        .expect("Failed to convert TPML_AC_CAPABILITIES into AttachedComponentCapabilities");

    assert_eq!(expected_outputs.len(), capabilities_from_tss.len());
    expected_outputs
        .iter()
        .zip(capabilities_from_tss.as_ref())
        .for_each(|(expected, actual)| assert_eq!(expected, actual));

    let actual_tpml_ac_capabilities = TPML_AC_CAPABILITIES::from(capabilities_from_vec);

    assert_eq!(
        expected_tpml_ac_capabilities.count,
        actual_tpml_ac_capabilities.count,
    );
    for index in 0..expected_tpml_ac_capabilities.count as usize {
        assert_eq!(
            expected_tpml_ac_capabilities.acCapabilities[index].tag,
            actual_tpml_ac_capabilities.acCapabilities[index].tag,
        );
        assert_eq!(
            expected_tpml_ac_capabilities.acCapabilities[index].data,
            actual_tpml_ac_capabilities.acCapabilities[index].data,
        );
    }
}

#[test]
fn test_invalid_conversions() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        AttachedComponentCapabilities::try_from(vec![
            AttachedComponentOutput::new(
                AttachedComponentCapability::Any,
                10
            );
            AttachedComponentCapabilities::MAX_SIZE + 1
        ]),
        "Converting a vector with too many elements did not produce the expected error",
    );

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        AttachedComponentCapabilities::try_from(TPML_AC_CAPABILITIES {
            count: AttachedComponentCapabilities::MAX_SIZE as u32 + 1,
            acCapabilities: [TPMS_AC_OUTPUT::default(); 128],
        }),
        "Converting a TPML_AC_CAPABILITIES with an invalid count did not produce the expected error",
    );

    let invalid_tpml_ac_capabilities = TPML_AC_CAPABILITIES {
        count: 1,
        acCapabilities: [TPMS_AC_OUTPUT { tag: 3, data: 0 }; 128],
    };
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        AttachedComponentCapabilities::try_from(invalid_tpml_ac_capabilities),
        "Converting a TPML_AC_CAPABILITIES with an invalid TPM_AT tag did not produce the expected error",
    );
}
