// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Result,
    ffi::data_zeroize::FfiDataZeroize,
    handles::ObjectHandle,
    structures::{Auth, PublicTemplate, SensitiveCreate, SensitiveData},
    tss2_esys::{ESYS_TR, TPM2B_SENSITIVE_CREATE, TPM2B_TEMPLATE},
};
use std::convert::TryInto;
use zeroize::Zeroize;

/// Owns the FFI inputs to `Esys_CreateLoaded` and zeroizes them on drop.
pub(crate) struct CreateLoadedCommandInputHandler {
    ffi_parent_handle: ESYS_TR,
    ffi_in_sensitive: TPM2B_SENSITIVE_CREATE,
    ffi_in_public: TPM2B_TEMPLATE,
}

impl CreateLoadedCommandInputHandler {
    pub(crate) fn create(
        parent_handle: ObjectHandle,
        public_template: PublicTemplate,
        auth_value: Option<Auth>,
        sensitive_data: Option<SensitiveData>,
    ) -> Result<Self> {
        Ok(Self {
            ffi_parent_handle: parent_handle.into(),
            ffi_in_sensitive: SensitiveCreate::new(
                auth_value.unwrap_or_default(),
                sensitive_data.unwrap_or_default(),
            )
            .try_into()?,
            ffi_in_public: public_template.into(),
        })
    }

    pub(crate) const fn ffi_parent_handle(&self) -> ESYS_TR {
        self.ffi_parent_handle
    }

    pub(crate) const fn ffi_in_sensitive(&self) -> &TPM2B_SENSITIVE_CREATE {
        &self.ffi_in_sensitive
    }

    pub(crate) const fn ffi_in_public(&self) -> &TPM2B_TEMPLATE {
        &self.ffi_in_public
    }
}

impl Zeroize for CreateLoadedCommandInputHandler {
    fn zeroize(&mut self) {
        self.ffi_parent_handle.zeroize();
        self.ffi_in_sensitive.ffi_data_zeroize();
        self.ffi_in_public.ffi_data_zeroize();
    }
}

impl Drop for CreateLoadedCommandInputHandler {
    fn drop(&mut self) {
        self.zeroize();
    }
}
