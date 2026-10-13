import { PII_TYPES, type PiiType } from './protocol.ts'

const piiNames: Record<PiiType, [string, string]> = {
  email: ['email address', 'email addresses'], ip_address: ['IP address', 'IP addresses'], phone: ['phone number', 'phone numbers'],
  mac_address: ['MAC address', 'MAC addresses'], iban: ['IBAN', 'IBANs'], credit_card: ['credit card number', 'credit card numbers'],
  swift_code: ['SWIFT code', 'SWIFT codes'], financial_account: ['account number', 'account numbers'], date_of_birth: ['date of birth', 'dates of birth'],
  username: ['username', 'usernames'], employee_id: ['employee ID', 'employee IDs'], customer_id: ['customer ID', 'customer IDs'],
  patient_id: ['patient ID', 'patient IDs'], student_id: ['student ID', 'student IDs'], applicant_id: ['applicant ID', 'applicant IDs'],
  tax_id: ['tax ID', 'tax IDs'], social_id: ['social security ID', 'social security IDs'], health_insurance_id: ['health insurance number', 'health insurance numbers'],
  physician_id: ['physician number', 'physician numbers'], passport_number: ['passport number', 'passport numbers'], id_card_number: ['ID card number', 'ID card numbers'],
  driver_license: ["driver's license number", "driver's license numbers"], license_plate: ['license plate', 'license plates'], ssn: ['SSN', 'SSNs'],
  national_id: ['national ID', 'national IDs'],
}

/** The approval question; counts come from the broker's offer, never from model arguments. */
export function disclosureQuestion(counts: Record<string, unknown>): string | undefined {
  const parts = PII_TYPES.flatMap(type => {
    const count = counts[type]
    return Number.isSafeInteger(count) && Number(count) > 0 ? [`${count} ${piiNames[type][Number(count) === 1 ? 0 : 1]}`] : []
  })
  if (!parts.length) return undefined
  const list = parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}`
  return `Patronus: Reveal ${list} from this result to the AI agent once? The values will be sent to its model. Deny to keep them masked.`
}
