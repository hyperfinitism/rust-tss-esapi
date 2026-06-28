// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Context, Result, ReturnCode,
    constants::AttachedComponentCapability,
    handles::{AttachedComponentHandle, AuthHandle, ObjectHandle, SessionHandle},
    interface_types::{YesNo, reserved_handles::NvAuth, session_handles::PolicySession},
    structures::{AttachedComponentCapabilities, AttachedComponentOutput, MaxBuffer, Name},
    tss2_esys::{Esys_AC_GetCapability, Esys_AC_Send, Esys_Policy_AC_SendSelect},
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;

impl Context {
    /// Get current capability information from an attached component.
    ///
    /// # Arguments
    ///
    /// * `ac` - The [attached component handle][AttachedComponentHandle] to query.
    /// * `capability` - The first [attached component capability][AttachedComponentCapability]
    ///   selector to return.
    /// * `count` - The maximum number of capability entries to return.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > The purpose of this command is to obtain information about an Attached
    /// > Component referenced by an AC handle.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    ///
    /// * The [attached component capability data][AttachedComponentCapabilities].
    /// * A boolean indicating whether more capability data is available.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::constants::AttachedComponentCapability;
    /// # use tss_esapi::handles::{AttachedComponentHandle, AttachedComponentTpmHandle};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// let ac_tpm_handle = AttachedComponentTpmHandle::new(0x9000_0000)
    ///     .expect("Failed to create attached component TPM handle");
    /// let ac_handle = context
    ///     .tr_from_tpm_public(ac_tpm_handle.into())
    ///     .map(AttachedComponentHandle::from)
    ///     .expect("Failed to get attached component ESYS handle");
    ///
    /// let (_capabilities, _more) = context
    ///     .ac_get_capability(ac_handle, AttachedComponentCapability::Any, 16)
    ///     .expect("Failed to call ac_get_capability");
    /// ```
    pub fn ac_get_capability(
        &mut self,
        ac: AttachedComponentHandle,
        capability: AttachedComponentCapability,
        count: u32,
    ) -> Result<(AttachedComponentCapabilities, bool)> {
        let mut more_data = YesNo::No.into();
        let mut capability_data_ptr = null_mut();

        ReturnCode::ensure_success(
            unsafe {
                Esys_AC_GetCapability(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    ac.into(),
                    capability.into(),
                    count,
                    &mut more_data,
                    &mut capability_data_ptr,
                )
            },
            |ret| {
                error!(
                    "Error when getting attached component capabilities: {:#010X}",
                    ret
                );
            },
        )?;

        Ok((
            AttachedComponentCapabilities::try_from(Context::ffi_data_to_owned(
                capability_data_ptr,
            )?)?,
            YesNo::try_from(more_data)?.into(),
        ))
    }

    /// Send data to an attached component and receive an attached component
    /// output value.
    ///
    /// # Arguments
    ///
    /// * `send_object` - The [object handle][ObjectHandle] associated with the
    ///   command sent to the attached component.
    /// * `auth_handle` - The [authorization source][NvAuth] for the attached
    ///   component aliased NV index.
    /// * `ac` - The [attached component handle][AttachedComponentHandle] that
    ///   receives the command.
    /// * `ac_data_in` - The [input data][MaxBuffer] sent to the attached component.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > The purpose of this command is to send (copy) a loaded object from the
    /// > TPM to an Attached Component.
    ///
    /// # Returns
    ///
    /// The [attached component output][AttachedComponentOutput] returned by the
    /// attached component.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::attributes::SessionAttributes;
    /// # use tss_esapi::constants::SessionType;
    /// # use tss_esapi::handles::{AttachedComponentHandle, AttachedComponentTpmHandle, ObjectHandle};
    /// # use tss_esapi::interface_types::{
    /// #     algorithm::HashingAlgorithm,
    /// #     reserved_handles::NvAuth,
    /// #     session_handles::AuthSession,
    /// # };
    /// # use tss_esapi::structures::{MaxBuffer, SymmetricDefinition};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// let session = context
    ///     .start_auth_session(
    ///         None,
    ///         None,
    ///         None,
    ///         SessionType::Hmac,
    ///         SymmetricDefinition::AES_256_CFB,
    ///         HashingAlgorithm::Sha256,
    ///     )
    ///     .expect("Failed to create session")
    ///     .expect("Received invalid handle");
    /// let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    ///     .with_decrypt(true)
    ///     .with_encrypt(true)
    ///     .build();
    /// context
    ///     .tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    ///     .expect("Failed to set attributes on session");
    /// context.set_sessions((Some(AuthSession::from(session)), None, None));
    ///
    /// let ac_tpm_handle = AttachedComponentTpmHandle::new(0x9000_0000)
    ///     .expect("Failed to create attached component TPM handle");
    /// let ac_handle = context
    ///     .tr_from_tpm_public(ac_tpm_handle.into())
    ///     .map(AttachedComponentHandle::from)
    ///     .expect("Failed to get attached component ESYS handle");
    ///
    /// let _output = context
    ///     .ac_send(
    ///         ObjectHandle::Null,
    ///         NvAuth::Owner,
    ///         ac_handle,
    ///         MaxBuffer::default(),
    ///     )
    ///     .expect("Failed to call ac_send");
    /// ```
    pub fn ac_send(
        &mut self,
        send_object: ObjectHandle,
        auth_handle: NvAuth,
        ac: AttachedComponentHandle,
        ac_data_in: MaxBuffer,
    ) -> Result<AttachedComponentOutput> {
        let mut ac_data_in = ac_data_in.into();
        let mut ac_data_out_ptr = null_mut();

        ReturnCode::ensure_success(
            unsafe {
                Esys_AC_Send(
                    self.mut_context(),
                    send_object.into(),
                    AuthHandle::from(auth_handle).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    ac.into(),
                    &mut ac_data_in,
                    &mut ac_data_out_ptr,
                )
            },
            |ret| {
                error!(
                    "Error when sending data to attached component: {:#010X}",
                    ret
                );
            },
        )?;

        AttachedComponentOutput::try_from(Context::ffi_data_to_owned(ac_data_out_ptr)?)
    }

    /// Cause conditional gating of a policy based on selected `AC_Send`
    /// parameters.
    ///
    /// # Arguments
    ///
    /// * `policy_session` - The [policy session][PolicySession] being extended.
    /// * `object_name` - The [name][Name] of the object used as `send_object`
    ///   in `AC_Send`.
    /// * `auth_handle_name` - The [name][Name] of the authorization handle used
    ///   by `AC_Send`.
    /// * `ac_name` - The [name][Name] of the attached component.
    /// * `include_object` - Flag indicating if `object_name` will be included in
    ///   the policy calculation.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command allows qualification of the sending (copying) of an Object
    /// > to an Attached Component (AC). Qualification includes selection of the
    /// > receiving AC and the method of authentication for the AC, and, in certain
    /// > circumstances, the Object to be sent may be specified.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::convert::TryFrom;
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::attributes::SessionAttributesBuilder;
    /// # use tss_esapi::constants::SessionType;
    /// # use tss_esapi::interface_types::{
    /// #     algorithm::HashingAlgorithm,
    /// #     session_handles::PolicySession,
    /// # };
    /// # use tss_esapi::structures::{Name, SymmetricDefinition};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// let trial_session = context
    ///     .start_auth_session(
    ///         None,
    ///         None,
    ///         None,
    ///         SessionType::Trial,
    ///         SymmetricDefinition::AES_256_CFB,
    ///         HashingAlgorithm::Sha256,
    ///     )
    ///     .expect("Start auth session failed")
    ///     .expect("Start auth session returned a NONE handle");
    /// let policy_session = PolicySession::try_from(trial_session)
    ///     .expect("Failed to convert auth session into policy session");
    ///
    /// let object_name = Name::try_from(vec![0x00, 0x0b, 0x11, 0x22])
    ///     .expect("Failed to create object name");
    /// let auth_handle_name = Name::try_from(vec![0x00, 0x0b, 0x33, 0x44])
    ///     .expect("Failed to create auth handle name");
    /// let ac_name = Name::try_from(vec![0x90, 0x00, 0x00, 0x00])
    ///     .expect("Failed to create attached component name");
    ///
    /// context.policy_ac_send_select(
    ///         policy_session,
    ///         object_name,
    ///         auth_handle_name,
    ///         ac_name,
    ///         true,
    ///     )
    ///     .expect("Failed to call policy_ac_send_select");
    /// ```
    pub fn policy_ac_send_select(
        &mut self,
        policy_session: PolicySession,
        object_name: Name,
        auth_handle_name: Name,
        ac_name: Name,
        include_object: bool,
    ) -> Result<()> {
        let mut object_name = object_name.into();
        let mut auth_handle_name = auth_handle_name.into();
        let mut ac_name = ac_name.into();

        ReturnCode::ensure_success(
            unsafe {
                Esys_Policy_AC_SendSelect(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut object_name,
                    &mut auth_handle_name,
                    &mut ac_name,
                    YesNo::from(include_object).into(),
                )
            },
            |ret| {
                error!("Error when computing policy AC send select: {:#010X}", ret);
            },
        )
    }
}
