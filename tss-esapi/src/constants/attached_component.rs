// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Error, Result, WrapperErrorKind,
    constants::tss::{TPM_AT_ANY, TPM_AT_ERROR, TPM_AT_PV1, TPM_AT_VEND},
    tss2_esys::TPM_AT,
};
use log::error;
use std::convert::TryFrom;

/// Attached component capability selector or output tag.
///
/// # Details
/// This corresponds to `TPM_AT`, defined in the TPM 2.0 Structures
/// specification, part 2, section 16.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachedComponentCapability {
    /// In a command, a non-specific request for attached-component information.
    /// In a response, indicates that `outputData` is not meaningful.
    Any,
    /// Indicates a TCG-defined, device-specific error.
    Error,
    /// Indicates the most significant 32 bits of a pairing value for the
    /// attached component.
    PairingValue1,
    /// Vendor-specific attached-component capability selector or output tag.
    ///
    /// Values from `TPM_AT_VEND` (`0x80000000`) through `0xFFFFFFFF` are
    /// reserved for vendor-specific use.
    VendorSpecific(TPM_AT),
}

impl AttachedComponentCapability {
    /// Creates a vendor-specific attached component capability selector or
    /// output tag.
    ///
    /// # Errors
    /// * if `value` is not in the vendor-specific TPM_AT range, an
    ///   `InvalidParam` wrapper error is returned.
    pub fn new_vendor_specific(value: TPM_AT) -> Result<Self> {
        if value < TPM_AT_VEND {
            error!(
                "Value = {} is not in the TPM_AT vendor-specific range",
                value
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(Self::VendorSpecific(value))
    }

    /// Returns the wrapped `TPM_AT` value.
    pub const fn value(&self) -> TPM_AT {
        match self {
            Self::Any => TPM_AT_ANY,
            Self::Error => TPM_AT_ERROR,
            Self::PairingValue1 => TPM_AT_PV1,
            Self::VendorSpecific(value) => *value,
        }
    }
}

impl From<AttachedComponentCapability> for TPM_AT {
    fn from(capability: AttachedComponentCapability) -> Self {
        capability.value()
    }
}

impl TryFrom<TPM_AT> for AttachedComponentCapability {
    type Error = Error;

    fn try_from(capability: TPM_AT) -> Result<Self> {
        match capability {
            TPM_AT_ANY => Ok(Self::Any),
            TPM_AT_ERROR => Ok(Self::Error),
            TPM_AT_PV1 => Ok(Self::PairingValue1),
            value if value >= TPM_AT_VEND => Ok(Self::VendorSpecific(value)),
            value => {
                error!("Value = {} did not match any TPM_AT value", value);
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}
