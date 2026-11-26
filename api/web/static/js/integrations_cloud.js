// Integrations page: the cloud exposure connectors (AWS, Azure, OCI), Zscaler (OneAPI) and Okta, all read only. Loaded before the page script, which
// spreads CLOUD_VENDOR_FIELDS into VENDOR_FIELDS. All read-only; secrets are stored encrypted and never shown again.
const CLOUD_VENDOR_FIELDS = {
  aws: [
    {key:'access_key_id',     label:'Access Key ID',      type:'text',     placeholder:'AKIA...', required:true},
    {key:'secret_access_key', label:'Secret Access Key',  type:'password', placeholder:'', required:true},
    {key:'role_arn',          label:'Role to assume (other accounts, optional)', type:'text', placeholder:'arn:aws:iam::123456789012:role/ctem-read', required:false},
    {key:'regions',           label:'Regions (comma separated; blank = every enabled region)', type:'text', placeholder:'us-east-1, us-west-2', required:false},
    {key:'create_devices',    label:'Add cloud instances CTEM has never seen', type:'checkbox', required:false},
  ],
  azure: [
    {key:'tenant_id',     label:'Tenant (directory) ID',   type:'text',     placeholder:'00000000-0000-0000-0000-000000000000', required:true},
    {key:'client_id',     label:'Client (application) ID', type:'text',     placeholder:'00000000-0000-0000-0000-000000000000', required:true},
    {key:'client_secret', label:'Client secret',           type:'password', placeholder:'', required:true},
    {key:'subscriptions', label:'Subscription IDs (comma separated; blank = every subscription the app can read)', type:'text', placeholder:'', required:false},
    {key:'azure_cloud',   label:'Cloud', type:'select', options:['public', 'usgov'], optionLabels:{public:'Azure (public)', usgov:'Azure US Government'}, required:false},
    {key:'create_devices', label:'Add cloud instances CTEM has never seen', type:'checkbox', required:false},
  ],
  zscaler: [
    {key:'vanity_domain', label:'ZIdentity vanity domain (the "acme" in acme.zslogin.net)', type:'text', placeholder:'acme', required:true},
    {key:'client_id',     label:'OneAPI client ID', type:'text', placeholder:'', required:true},
    {key:'client_secret', label:'OneAPI client secret (give the client view-only roles in each product)', type:'password', placeholder:'', required:true},
  ],
  okta: [
    {key:'base_url',       label:'Okta domain', type:'text', placeholder:'https://acme.okta.com', required:true},
    {key:'api_token',      label:'API token (create it as a Read-Only Administrator)', type:'password', placeholder:'', required:true},
    {key:'factor_budget',  label:'MFA lookups per sync (default 3000; people on computers go first)', type:'text', placeholder:'3000', required:false},
    {key:'app_budget',     label:'App list lookups per sync (default 3000; each person\'s apps are refreshed weekly)', type:'text', placeholder:'3000', required:false},
    {key:'device_interval_days', label:'Device pull every N days (default 7; it is slow, about 1 minute per 750 computers; 0 = every sync)', type:'text', placeholder:'7', required:false},
    {key:'create_devices', label:'Add Okta-registered computers CTEM has never seen (active in the last 90 days)', type:'checkbox', required:false},
  ],
  persona: [
    {key:'api_key',        label:'API key (reads inquiries and templates)', type:'password', placeholder:'persona_production_...', required:true},
    {key:'badge_templates', label:'Templates whose passes earn the IDV badge (itmpl_... comma separated; blank = any started by an API key)', type:'text', placeholder:'itmpl_..., itmpl_...', required:false},
    {key:'idv_page',       label:'Enable IDV approval (the IDV page, its review queue and sidebar link; off = only the IDV badges show)', type:'checkbox', required:false, default:true},
    {key:'allow_actions',  label:'Allow approve, decline and service-desk requests (needs a key with those permissions)', type:'checkbox', required:false},
    {key:'action_api_key', label:'API key for those actions (blank = the key above)', type:'password', placeholder:'persona_production_...', required:false},
    {key:'template_id',    label:'Inquiry template for government ID + selfie (itmpl_...)', type:'text', placeholder:'itmpl_...', required:false},
    {key:'selfie_template_id', label:'Inquiry template for a selfie only, for people with a verified ID on file (itmpl_...; blank = always ID + selfie)', type:'text', placeholder:'itmpl_...', required:false},
    {key:'detail_budget',  label:'Device lookups per sync (default 300)', type:'text', placeholder:'300', required:false},
  ],
  twilio: [
    {key:'account_sid',    label:'Account SID', type:'text', placeholder:'AC...', required:true},
    {key:'api_key_sid',    label:'API key SID (a Restricted key: Messaging, Messages Create and Read only)', type:'text', placeholder:'SK...', required:true},
    {key:'api_key_secret', label:'API key secret', type:'password', placeholder:'', required:true},
    {key:'from_number',    label:'Send from (E.164)', type:'text', placeholder:'+15550100100', required:true},
  ],
  oci: [
    {key:'tenancy_ocid',   label:'Tenancy OCID', type:'text', placeholder:'ocid1.tenancy.oc1..', required:true},
    {key:'user_ocid',      label:'User OCID',    type:'text', placeholder:'ocid1.user.oc1..', required:true},
    {key:'fingerprint',    label:'API key fingerprint', type:'text', placeholder:'12:34:56:...', required:true},
    {key:'private_key',    label:'API signing private key (PEM)', type:'secret_text', placeholder:'-----BEGIN PRIVATE KEY-----', required:true},
    {key:'key_passphrase', label:'Key passphrase (if the key has one)', type:'password', placeholder:'', required:false},
    {key:'regions',        label:'Regions (comma separated)', type:'text', placeholder:'us-ashburn-1, us-phoenix-1', required:true},
    {key:'create_devices', label:'Add cloud instances CTEM has never seen', type:'checkbox', required:false},
  ],
};
