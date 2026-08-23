// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_duplicate {
    use crate::common::SwtpmSession;
    use std::convert::TryFrom;
    use std::convert::TryInto;
    use tss_esapi::Context;
    use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
    use tss_esapi::constants::SessionType;
    use tss_esapi::handles::ObjectHandle;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        reserved_handles::Hierarchy,
        session_handles::PolicySession,
    };
    use tss_esapi::structures::SymmetricDefinition;
    use tss_esapi::structures::{
        EccPoint, EccScheme, KeyDerivationFunctionScheme, PublicBuilder,
        PublicEccParametersBuilder, SymmetricDefinitionObject,
    };

    #[test]
    fn test_duplicate_and_import() {
        // Use a shared swtpm so all contexts share TPM state (primary key seeds).
        let swtpm = SwtpmSession::new();
        let mut context = swtpm.create_session_context();

        // First: create a target parent object.
        // The key that we will duplicate will be a child of this target parent.
        let parent_object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(false)
            .with_restricted(true)
            .build()
            .expect("Attributes to be valid");

        let public_parent = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(parent_object_attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_is_signing_key(false)
                    .with_is_decryption_key(true)
                    .with_restricted(true)
                    .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .expect("Params to be valid"),
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .expect("public to be valid");

        let new_parent_handle = context
            .create_primary(
                Hierarchy::Owner,
                public_parent.clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        // The name of the parent will be used to restrict duplication to
        // only this one parent.
        let parent_name = context.read_public(new_parent_handle).unwrap().1;

        drop(context);

        // Trial session will be used to compute a policy digest.
        // The policy will allow key duplication to one specified target parent.
        // The target parent would be selected using "parent_name".
        let mut context = Context::new(swtpm.tcti()).unwrap();

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

        let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let policy_session = PolicySession::try_from(trial_session)
            .expect("Failed to convert auth session into policy session");

        context
            .policy_duplication_select(
                policy_session,
                Vec::<u8>::new().try_into().unwrap(),
                parent_name.clone(),
                false,
            )
            .expect("Policy duplication select");

        // Policy digest will be used when constructing the child key.
        // It will allow the newly constructed key to be duplicated but
        // only to one specified parent.
        let digest = context
            .policy_get_digest(policy_session)
            .expect("Could retrieve digest");

        drop(context);
        let mut context = swtpm.create_session_context();

        // Fixed TPM and Fixed Parent should be "false" for an object
        // to be eligible for duplication
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(false)
            .with_fixed_parent(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Attributes to be valid");

        let public_child = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            // Use policy digest computed using the trial session
            .with_auth_policy(digest)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_is_signing_key(false)
                    .with_is_decryption_key(true)
                    .with_restricted(false)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .expect("Params to be valid"),
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .expect("public to be valid");

        // Re-create the new parent again.
        // Since the key specification did not change it will be the same parent
        // that was used to get the "parent_name".
        // In real world the new parent will likely be persisted in the TPM.
        let new_parent_handle: ObjectHandle = context
            .create_primary(
                Hierarchy::Owner,
                public_parent.clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle
            .into();

        let parent_of_object_to_duplicate_handle = context
            .create_primary(Hierarchy::Owner, public_parent, None, None, None, None)
            .unwrap()
            .key_handle;

        let result = context
            .create(
                parent_of_object_to_duplicate_handle,
                public_child,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let object_to_duplicate_handle: ObjectHandle = context
            .load(
                parent_of_object_to_duplicate_handle,
                result.out_private.clone(),
                result.out_public,
            )
            .unwrap()
            .into();

        // Object name of the duplicated object is needed to satisfy
        // real policy session.
        let object_name = context
            .read_public(object_to_duplicate_handle.into())
            .unwrap()
            .1;

        context.set_sessions((None, None, None));

        let policy_auth_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                policy_auth_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let policy_session = PolicySession::try_from(policy_auth_session)
            .expect("Failed to convert auth session into policy session");

        // Even if object name is not included in the policy digest ("false" as 3rd parameter)
        // Correct name needs to be set or the policy will fail.
        context
            .policy_duplication_select(policy_session, object_name, parent_name, false)
            .unwrap();
        context.set_sessions((Some(policy_auth_session), None, None));

        // Duplicate the object to new parent.
        let (data, duplicate, secret) = context
            .duplicate(
                object_to_duplicate_handle,
                new_parent_handle,
                None,
                SymmetricDefinitionObject::Null,
            )
            .unwrap();
        eprintln!("D: {data:?}, P: {duplicate:?}, S: {secret:?}");

        // Public is also needed when transferring the duplicatee
        // for integrity validation.
        let public = context
            .read_public(object_to_duplicate_handle.into())
            .unwrap()
            .0;

        let session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        context
            .tr_sess_set_attributes(
                session.unwrap(),
                session_attributes,
                session_attributes_mask,
            )
            .unwrap();
        context.set_sessions((session, None, None));

        // Try to import the duplicated object.
        // Most parameters (with the exception of public) are passed from
        // the values returned from the call to `duplicate`.
        let private = context
            .import(
                new_parent_handle,
                Some(data),
                public,
                duplicate,
                secret,
                SymmetricDefinitionObject::Null,
            )
            .unwrap();

        eprintln!("P: {private:?}");
    }
}

mod test_rewrap {
    use crate::common::SwtpmSession;
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        Context,
        attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
        constants::SessionType,
        handles::SessionHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            ecc::EccCurve,
            key_bits::RsaKeyBits,
            reserved_handles::Hierarchy,
            session_handles::PolicySession,
        },
        structures::{
            EccPoint, EccScheme, KeyDerivationFunctionScheme, PublicBuilder,
            PublicEccParametersBuilder, RsaExponent, SymmetricDefinition,
            SymmetricDefinitionObject,
        },
        utils::create_restricted_decryption_rsa_public,
    };

    #[test]
    fn test_duplicate_rewrap_import_and_load() {
        let swtpm = SwtpmSession::new();
        let mut context = Context::new(swtpm.tcti()).expect("Failed to create Context");
        let old_parent_public = create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .expect("Failed to create old parent public area");
        let new_parent_public = create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_256_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .expect("Failed to create new parent public area");
        let old_parent = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, old_parent_public, None, None, None, None)
            })
            .expect("Failed to create old parent")
            .key_handle;
        let new_parent = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, new_parent_public, None, None, None, None)
            })
            .expect("Failed to create new parent")
            .key_handle;
        let old_parent_name = context
            .read_public(old_parent)
            .expect("Failed to read old parent")
            .1;

        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Failed to create trial session")
            .expect("Received invalid handle");
        let trial_policy =
            PolicySession::try_from(trial_session).expect("Failed to convert trial session");
        context
            .policy_duplication_select(
                trial_policy,
                Vec::<u8>::new()
                    .try_into()
                    .expect("Failed to create empty Name"),
                old_parent_name.clone(),
                false,
            )
            .expect("Failed to compute duplication policy");
        let policy_digest = context
            .policy_get_digest(trial_policy)
            .expect("Failed to get policy digest");
        context
            .flush_context(SessionHandle::from(trial_session).into())
            .expect("Failed to flush trial session");

        let child_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(false)
            .with_fixed_parent(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to create child attributes");
        let child_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(child_attributes)
            .with_auth_policy(policy_digest)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_is_signing_key(false)
                    .with_is_decryption_key(true)
                    .with_restricted(false)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .expect("Failed to create child parameters"),
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .expect("Failed to create child public area");
        let create_result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(new_parent, child_public, None, None, None, None)
            })
            .expect("Failed to create child object");
        let child_public = create_result.out_public.clone();
        let child = context
            .execute_with_nullauth_session(|ctx| {
                ctx.load(
                    new_parent,
                    create_result.out_private,
                    create_result.out_public,
                )
            })
            .expect("Failed to load child object");
        let child_name = context
            .read_public(child)
            .expect("Failed to read child object")
            .1;

        let policy_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Failed to create policy session")
            .expect("Received invalid handle");
        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        context
            .tr_sess_set_attributes(policy_session, attributes, mask)
            .expect("Failed to set policy session attributes");
        let policy =
            PolicySession::try_from(policy_session).expect("Failed to convert policy session");
        context
            .policy_duplication_select(policy, child_name.clone(), old_parent_name, false)
            .expect("Failed to satisfy duplication policy");
        context.set_sessions((Some(policy_session), None, None));
        let (encryption_key, duplicate, in_sym_seed) = context
            .duplicate(
                child.into(),
                old_parent.into(),
                None,
                SymmetricDefinitionObject::Null,
            )
            .expect("Failed to duplicate child object");
        context.clear_sessions();
        context
            .flush_context(SessionHandle::from(policy_session).into())
            .expect("Failed to flush policy session");

        let (out_duplicate, out_sym_seed) = context
            .execute_with_nullauth_session(|ctx| {
                ctx.rewrap(
                    old_parent.into(),
                    new_parent.into(),
                    duplicate,
                    child_name.clone(),
                    in_sym_seed,
                )
            })
            .expect("Failed to re-wrap duplicated object");
        context
            .flush_context(child.into())
            .expect("Failed to flush child");
        let imported_private = context
            .execute_with_nullauth_session(|ctx| {
                ctx.import(
                    new_parent.into(),
                    Some(encryption_key),
                    child_public.clone(),
                    out_duplicate,
                    out_sym_seed,
                    SymmetricDefinitionObject::Null,
                )
            })
            .expect("Failed to import re-wrapped object");
        let imported_child = context
            .execute_with_nullauth_session(|ctx| {
                ctx.load(new_parent, imported_private, child_public)
            })
            .expect("Failed to load imported object");
        let imported_name = context
            .read_public(imported_child)
            .expect("Failed to read imported object")
            .1;
        assert_eq!(child_name, imported_name);

        context
            .flush_context(imported_child.into())
            .expect("Failed to flush imported child");
        context
            .flush_context(old_parent.into())
            .expect("Failed to flush old parent");
        context
            .flush_context(new_parent.into())
            .expect("Failed to flush new parent");
    }
}
