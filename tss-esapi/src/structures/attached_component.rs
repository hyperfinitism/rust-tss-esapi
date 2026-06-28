// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Error, Result,
    constants::AttachedComponentCapability,
    tss2_esys::{TPMS_AC_OUTPUT, UINT32},
};
use std::convert::TryFrom;

/// Output data returned by an attached component.
///
/// # Details
/// This corresponds to `TPMS_AC_OUTPUT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachedComponentOutput {
    tag: AttachedComponentCapability,
    data: UINT32,
}

impl AttachedComponentOutput {
    /// Creates a new attached component output value.
    pub const fn new(tag: AttachedComponentCapability, data: UINT32) -> Self {
        Self { tag, data }
    }

    /// Returns the attached component output tag.
    pub const fn tag(&self) -> AttachedComponentCapability {
        self.tag
    }

    /// Returns the attached component output data.
    pub const fn data(&self) -> UINT32 {
        self.data
    }
}

impl TryFrom<TPMS_AC_OUTPUT> for AttachedComponentOutput {
    type Error = Error;

    fn try_from(tss_output: TPMS_AC_OUTPUT) -> Result<Self> {
        Ok(Self {
            tag: AttachedComponentCapability::try_from(tss_output.tag)?,
            data: tss_output.data,
        })
    }
}

impl From<AttachedComponentOutput> for TPMS_AC_OUTPUT {
    fn from(output: AttachedComponentOutput) -> Self {
        Self {
            tag: output.tag.into(),
            data: output.data,
        }
    }
}
