// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod attached_component_commands {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        Error, ReturnCode,
        constants::{
            AttachedComponentCapability, SessionType,
            return_code::{BaseError, TpmFormatZeroError},
        },
        error::{TpmFormatZeroResponseCode, TpmResponseCode},
        handles::{AttachedComponentHandle, ObjectHandle},
        interface_types::{
            algorithm::HashingAlgorithm, reserved_handles::NvAuth, session_handles::PolicySession,
        },
        structures::{MaxBuffer, Name, SymmetricDefinition},
    };

    #[test]
    fn test_ac_get_capability() {
        let mut context = create_ctx_without_session();

        match context.ac_get_capability(
            AttachedComponentHandle::from(0xfff),
            AttachedComponentCapability::Any,
            16,
        ) {
            Ok((_capabilities, _more_data)) => (),
            Err(Error::TssError(ReturnCode::Esapi(error)))
                if matches!(error.base_error(), BaseError::BadValue | BaseError::BadTr) =>
            {
                ()
            }
            Err(Error::TssError(ReturnCode::Tpm(TpmResponseCode::FormatZero(
                TpmFormatZeroResponseCode::Error(error),
            )))) if error.error_number() == TpmFormatZeroError::CommandCode => (),
            Err(error) => panic!("AC_GetCapability failed unexpectedly: {error:?}"),
        }
    }

    #[test]
    fn test_ac_send_uses_optional_sessions() {
        let mut context = create_ctx_without_session();

        let result = context.ac_send(
            ObjectHandle::Null,
            NvAuth::Owner,
            AttachedComponentHandle::from(0xfff),
            MaxBuffer::default(),
        );

        assert!(
            !matches!(
                result,
                Err(Error::WrapperError(
                    tss_esapi::WrapperErrorKind::MissingAuthSession
                ))
            ),
            "AC_Send should forward optional sessions instead of requiring session slot 1",
        );
    }

    #[test]
    fn test_policy_ac_send_select() {
        let mut context = create_ctx_without_session();

        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        let policy_session = PolicySession::try_from(trial_session)
            .expect("Failed to convert auth session into policy session");

        let object_name =
            Name::try_from(vec![0x00, 0x0b, 0x11, 0x22]).expect("Failed to create object name");
        let auth_handle_name = Name::try_from(vec![0x00, 0x0b, 0x33, 0x44])
            .expect("Failed to create auth handle name");
        let ac_name =
            Name::try_from(vec![0x90, 0x00, 0x00, 0x00]).expect("Failed to create AC name");

        match context.policy_ac_send_select(
            policy_session,
            object_name,
            auth_handle_name,
            ac_name,
            true,
        ) {
            Ok(()) => (),
            Err(Error::TssError(ReturnCode::Tpm(TpmResponseCode::FormatZero(
                TpmFormatZeroResponseCode::Error(error),
            )))) if error.error_number() == TpmFormatZeroError::CommandCode => (),
            Err(error) => panic!("Policy_AC_SendSelect failed unexpectedly: {error:?}"),
        }
    }
}
