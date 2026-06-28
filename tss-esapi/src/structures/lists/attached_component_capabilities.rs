// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Error, Result, WrapperErrorKind,
    structures::AttachedComponentOutput,
    tss2_esys::{TPML_AC_CAPABILITIES, TPMS_AC_OUTPUT},
};
use log::error;
use std::{convert::TryFrom, iter::IntoIterator, ops::Deref};

/// A list of attached component capability output values.
///
/// # Details
/// This corresponds to `TPML_AC_CAPABILITIES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedComponentCapabilities {
    capabilities: Vec<AttachedComponentOutput>,
}

impl AttachedComponentCapabilities {
    pub const MAX_SIZE: usize = Self::calculate_max_size();

    /// Returns the inner vector.
    pub fn into_inner(self) -> Vec<AttachedComponentOutput> {
        self.capabilities
    }

    /// Private function that calculates the maximum number of elements allowed
    /// in internal storage.
    const fn calculate_max_size() -> usize {
        crate::structures::capability_data::max_cap_size::<TPMS_AC_OUTPUT>()
    }
}

impl Deref for AttachedComponentCapabilities {
    type Target = Vec<AttachedComponentOutput>;

    fn deref(&self) -> &Self::Target {
        &self.capabilities
    }
}

impl AsRef<[AttachedComponentOutput]> for AttachedComponentCapabilities {
    fn as_ref(&self) -> &[AttachedComponentOutput] {
        self.capabilities.as_slice()
    }
}

impl TryFrom<Vec<AttachedComponentOutput>> for AttachedComponentCapabilities {
    type Error = Error;

    fn try_from(capabilities: Vec<AttachedComponentOutput>) -> Result<Self> {
        if capabilities.len() > Self::MAX_SIZE {
            error!(
                "Failed to convert Vec<AttachedComponentOutput> into AttachedComponentCapabilities, too many items (> {})",
                Self::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(Self { capabilities })
    }
}

impl IntoIterator for AttachedComponentCapabilities {
    type Item = AttachedComponentOutput;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.capabilities.into_iter()
    }
}

impl TryFrom<TPML_AC_CAPABILITIES> for AttachedComponentCapabilities {
    type Error = Error;

    fn try_from(tss_capabilities: TPML_AC_CAPABILITIES) -> Result<Self> {
        let count = usize::try_from(tss_capabilities.count).map_err(|e| {
            error!(
                "Failed to parse count in TPML_AC_CAPABILITIES as usize: {}",
                e
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        if count > Self::MAX_SIZE {
            error!(
                "Invalid size value in TPML_AC_CAPABILITIES (> {})",
                Self::MAX_SIZE,
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        tss_capabilities.acCapabilities[..count]
            .iter()
            .copied()
            .map(AttachedComponentOutput::try_from)
            .collect::<Result<Vec<AttachedComponentOutput>>>()
            .map(|capabilities| Self { capabilities })
    }
}

impl From<AttachedComponentCapabilities> for TPML_AC_CAPABILITIES {
    fn from(capabilities: AttachedComponentCapabilities) -> Self {
        let mut tss_capabilities: TPML_AC_CAPABILITIES = Default::default();
        for capability in capabilities {
            tss_capabilities.acCapabilities[tss_capabilities.count as usize] = capability.into();
            tss_capabilities.count += 1;
        }
        tss_capabilities
    }
}
