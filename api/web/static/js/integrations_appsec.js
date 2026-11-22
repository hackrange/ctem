// Integrations page: application security platforms (SAST and DAST). Loaded before the page script, which spreads
// APPSEC_VENDOR_FIELDS into VENDOR_FIELDS. Read-only connectors; the token is stored encrypted and never shown again.
const APPSEC_VENDOR_FIELDS = {
  github_code_review: [
    {key:'base_url',     label:'GitHub Code Review URL', type:'text', placeholder:'https://githubcodereview.acme.example', required:true},
    {key:'api_token',    label:'API token (scopes: reports, and external for DAST)', type:'password', placeholder:'gcr_...', required:true},
    {key:'min_severity', label:'Bring in findings from', type:'select', options:['medium', 'high', 'critical', 'low', 'info'],
      optionLabels:{critical:'Critical only', high:'High and up', medium:'Medium and up', low:'Low and up', info:'Everything'}, required:false},
    {key:'include_dast', label:'Include external sites and their DAST scans (needs the external scope)', type:'checkbox', required:false},
    {key:'include_archived', label:'Include archived repositories', type:'checkbox', required:false},
    {key:'no_push_exceptions', label:"Don't send exceptions approved in CTEM to GitHub Code Review", type:'checkbox', required:false},
    {key:'tag_map', label:'Tag repositories and sites (one per line: name pattern = tags)', type:'textarea', required:false,
      placeholder:'acme/claims-portal* = app:Claims Portal, exec_owner:Jane Doe\nclaims.acme.example = env:Prod'},
  ],
};
