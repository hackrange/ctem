// Integrations page: the cloud exposure connectors (AWS, Azure, OCI). Loaded before the page script, which
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
