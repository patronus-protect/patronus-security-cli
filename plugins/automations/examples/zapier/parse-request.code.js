// Patronus examples: read the request body of a "Catch Raw Hook" trigger.
// The plain "Catch Hook" trigger expands JSON-looking string values (for example a chat message
// such as {"order": "NL-204"}) into sub-fields, which leaves the original text empty. Parsing the
// raw body keeps every field exactly as sent. Input Data: raw_body (map "Raw Body" from step 1).
const body = JSON.parse(inputData.raw_body || '{}');
const text = value => (typeof value === 'string' ? value : '');
output = { case_id: text(body.case_id), message: text(body.message), question: text(body.question) };
