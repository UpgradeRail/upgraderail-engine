use serde::{Deserialize, Serialize};
use serde_json::Value;
use stellar_xdr::{
    Limits, ReadXdr, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationEvidence {
    pub raw_xdr: String,
    pub normalized: Option<NormalizedAuthorization>,
    pub normalization_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NormalizedAuthorization {
    pub credential_form: String,
    pub authorizing_identity: Value,
    pub invocation: NormalizedInvocation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NormalizedInvocation {
    pub function_kind: String,
    pub contract: Option<Value>,
    pub function: Option<String>,
    pub arguments: Vec<Value>,
    pub details: Option<Value>,
    pub sub_invocations: Vec<Self>,
}

pub fn normalize_authorization(raw_xdr: &str) -> AuthorizationEvidence {
    match SorobanAuthorizationEntry::from_xdr_base64(raw_xdr, Limits::none()) {
        Ok(entry) => AuthorizationEvidence {
            raw_xdr: raw_xdr.into(),
            normalized: Some(normalize_entry(&entry)),
            normalization_error: None,
        },
        Err(error) => AuthorizationEvidence {
            raw_xdr: raw_xdr.into(),
            normalized: None,
            normalization_error: Some(error.to_string()),
        },
    }
}

fn normalize_entry(entry: &SorobanAuthorizationEntry) -> NormalizedAuthorization {
    let (credential_form, authorizing_identity) = match &entry.credentials {
        SorobanCredentials::SourceAccount => ("source_account".into(), Value::Null),
        SorobanCredentials::Address(value) => ("address".into(), address_identity(value)),
        SorobanCredentials::AddressV2(value) => ("address_v2".into(), address_identity(value)),
        SorobanCredentials::AddressWithDelegates(value) => (
            "address_with_delegates".into(),
            serde_json::to_value(value).unwrap_or(Value::Null),
        ),
    };
    NormalizedAuthorization {
        credential_form,
        authorizing_identity,
        invocation: normalize_invocation(&entry.root_invocation),
    }
}

fn address_identity(value: &stellar_xdr::SorobanAddressCredentials) -> Value {
    serde_json::to_value(&value.address).unwrap_or(Value::Null)
}

fn normalize_invocation(value: &SorobanAuthorizedInvocation) -> NormalizedInvocation {
    let (function_kind, contract, function, arguments, details) = match &value.function {
        SorobanAuthorizedFunction::ContractFn(args) => (
            "contract_fn".into(),
            Some(serde_json::to_value(&args.contract_address).unwrap_or(Value::Null)),
            Some(args.function_name.to_string()),
            args.args.iter().map(scval_value).collect(),
            None,
        ),
        SorobanAuthorizedFunction::CreateContractHostFn(args) => (
            "create_contract_host_fn".into(),
            None,
            None,
            Vec::new(),
            Some(serde_json::to_value(args).unwrap_or(Value::Null)),
        ),
        SorobanAuthorizedFunction::CreateContractV2HostFn(args) => (
            "create_contract_v2_host_fn".into(),
            None,
            None,
            Vec::new(),
            Some(serde_json::to_value(args).unwrap_or(Value::Null)),
        ),
    };
    NormalizedInvocation {
        function_kind,
        contract,
        function,
        arguments,
        details,
        sub_invocations: value
            .sub_invocations
            .iter()
            .map(normalize_invocation)
            .collect(),
    }
}

fn scval_value(value: &stellar_xdr::ScVal) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::WriteXdr;

    #[test]
    fn protocol_28_authorization_xdr_retains_raw_and_normalized_evidence() {
        let raw = SorobanAuthorizationEntry::default()
            .to_xdr_base64(Limits::none())
            .unwrap();
        let evidence = normalize_authorization(&raw);
        assert_eq!(evidence.raw_xdr, raw);
        assert_eq!(
            evidence.normalized.unwrap().credential_form,
            "source_account"
        );
        assert!(evidence.normalization_error.is_none());
    }

    #[test]
    fn malformed_authorization_xdr_is_retained_for_review() {
        let evidence = normalize_authorization("not base64 XDR");
        assert_eq!(evidence.raw_xdr, "not base64 XDR");
        assert!(evidence.normalized.is_none());
        assert!(evidence.normalization_error.is_some());
    }
}
