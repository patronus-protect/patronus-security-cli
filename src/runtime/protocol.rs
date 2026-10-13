use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Incomplete,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approved,
    Dangerous,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PayloadCoverage {
    pub fields_total: usize,
    pub fields_scanned: usize,
    pub bytes_total: usize,
    pub bytes_scanned: usize,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeFinding {
    // Opaque field number: an object key or JSON pointer can itself contain secrets.
    pub field_id: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub category: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub status: JobStatus,
    pub verdict: Option<Verdict>,
    pub findings: Vec<RuntimeFinding>,
    pub coverage: PayloadCoverage,
    pub redacted: Option<Value>,
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<crate::ark::ScanNotice>,
    /// Private typed PII locations for a user-confirmed disclosure. Never part of
    /// a model-visible receipt: `findings` keep their fixed category labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosure: Vec<DisclosureSpan>,
}

/// A fixed set of PII types a user can confirm for disclosure. Scanner labels
/// outside this list never become revealable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    Email,
    IpAddress,
    Phone,
    MacAddress,
    Iban,
    CreditCard,
    SwiftCode,
    FinancialAccount,
    DateOfBirth,
    Username,
    EmployeeId,
    CustomerId,
    PatientId,
    StudentId,
    ApplicantId,
    TaxId,
    SocialId,
    HealthInsuranceId,
    PhysicianId,
    PassportNumber,
    IdCardNumber,
    DriverLicense,
    LicensePlate,
    Ssn,
    NationalId,
}

impl PiiType {
    /// Card security codes and expiry dates stay masked: they are authentication
    /// data rather than identifying personal data.
    pub fn from_scanner_label(label: &str) -> Option<Self> {
        Some(match label {
            "EMAIL" => Self::Email,
            "IP_ADDRESS" => Self::IpAddress,
            "PHONE" => Self::Phone,
            "MAC_ADDRESS" => Self::MacAddress,
            "IBAN" => Self::Iban,
            "CREDITCARD" => Self::CreditCard,
            "SWIFT_CODE" => Self::SwiftCode,
            "FINANCIAL_ACCOUNT_NUMBER" => Self::FinancialAccount,
            "DOB" => Self::DateOfBirth,
            "USERNAME" => Self::Username,
            "EMPLOYEE_ID" => Self::EmployeeId,
            "CUSTOMER_ID" => Self::CustomerId,
            "PATIENT_ID" => Self::PatientId,
            "STUDENT_ID" => Self::StudentId,
            "APPLICANT_ID" => Self::ApplicantId,
            "STEUERID" | "TAX_NUMBER_DE" => Self::TaxId,
            "SOCIALID" => Self::SocialId,
            "HEALTH_INSURANCE_NUMBER" => Self::HealthInsuranceId,
            "PHYSICIAN_NUMBER_LANR" => Self::PhysicianId,
            "PASSPORT_NUMBER" => Self::PassportNumber,
            "IDENTITY_CARD_NUMBER" => Self::IdCardNumber,
            "DRIVER_LICENSE_NUMBER" => Self::DriverLicense,
            "LICENSEPLATE" => Self::LicensePlate,
            "SSN" => Self::Ssn,
            "NATIONALID" => Self::NationalId,
            _ => return None,
        })
    }
}

/// One exact PII evidence span. `pii_type` is `None` for scanner labels outside
/// the fixed list; such spans always stay masked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisclosureSpan {
    pub field_id: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub pii_type: Option<PiiType>,
}

impl ScanOutcome {
    pub fn failed(reason: &str) -> Self {
        Self {
            status: JobStatus::Failed,
            verdict: None,
            findings: vec![],
            coverage: PayloadCoverage::default(),
            redacted: None,
            reason: Some(reason.into()),
            notice: None,
            disclosure: vec![],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitParams {
    #[serde(default)]
    pub policy_scope: Option<String>,
    pub session: String,
    pub direction: Direction,
    pub tool: String,
    pub call_id: String,
    pub payload: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupParams {
    pub session: String,
    pub scan_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareDisclosureParams {
    pub session: String,
    pub scan_id: String,
    pub reveal_pii: Vec<PiiType>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadDisclosedParams {
    pub session: String,
    pub scan_id: String,
    pub grant_id: String,
}
