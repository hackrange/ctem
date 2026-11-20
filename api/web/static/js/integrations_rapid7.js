// Rapid7 form fields; one Insight Platform key can cover AppSec + InsightVM cloud.
const R7_REGIONS = ['us','us2','us3','eu','ca','au','ap'];
Object.assign(VENDOR_FIELDS, {
rapid7_appsec: [
  {key:'region',     label:'Insight Region',  type:'select',   options:R7_REGIONS, required:true},
  {key:'api_key',    label:'Insight Platform API Key', type:'password', placeholder:'', required:true},
  {key:'min_severity', label:'Minimum Severity', type:'select', options:['HIGH','CRITICAL','MEDIUM','LOW'], required:false},
  {key:'max_findings', label:'Max Findings per Sync (blank = all)', type:'number', placeholder:'all', required:false},
],
rapid7_insightvm: [
  {key:'mode',       label:'Deployment',      type:'select',   options:['cloud','console'],
    optionLabels:{'cloud':'Insight Platform (cloud v4 API, API key)','console':'On-prem Security Console (v3 API)'}, required:true},
  {key:'region',     label:'Insight Region (cloud)', type:'select', options:R7_REGIONS, required:false},
  {key:'api_key',    label:'Insight Platform API Key (cloud)', type:'password', placeholder:'', required:false},
  {key:'min_severity', label:'Minimum Severity', type:'select', options:['Severe','Critical','Moderate'], required:false},
  {key:'max_assets', label:'Max Assets per Sync (blank = all)', type:'number', placeholder:'all', required:false},
  {key:'host',       label:'Console Host (on-prem)', type:'text', placeholder:'insightvm.acme.example.com', required:false},
  {key:'port',       label:'Console Port',    type:'number',   placeholder:'3780', required:false},
  {key:'username',   label:'Console Username', type:'text',    placeholder:'svc-ctem', required:false},
  {key:'password',   label:'Console Password', type:'password', placeholder:'', required:false},
  {key:'tls_skip_verify', label:'Skip certificate check (lab only)', type:'checkbox', placeholder:'', required:false},
],
rapid7_cloudsec: [
  {key:'base_url',   label:'InsightCloudSec URL', type:'text', placeholder:'https://us1.cloudsec.insight.rapid7.com', required:true},
  {key:'api_key',    label:'InsightCloudSec API Key (not a Command Platform key)', type:'password', placeholder:'', required:true},
  {key:'min_severity', label:'Minimum Insight Severity', type:'select', options:['high','critical','medium','low'], required:false},
  {key:'max_insights', label:'Max Insights per Sync (blank = all)', type:'number', placeholder:'all', required:false},
  {key:'max_findings', label:'Max Findings per Sync (blank = all)', type:'number', placeholder:'all', required:false},
],
});
