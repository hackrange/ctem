// Rapid7 and Tanium form fields; one Insight Platform key can cover AppSec + InsightVM cloud. Pull options choose
// which tool brings vulnerabilities, software and disk encryption; a CVE both tools report is one finding.
const R7_REGIONS = ['us','us2','us3','eu','ca','au','ap'];
Object.assign(VENDOR_FIELDS, {
rapid7_appsec: [
  {key:'region',     label:'Insight Region',  type:'select',   options:R7_REGIONS, required:true},
  {key:'api_key',    label:'Insight Platform API Key', type:'password', placeholder:'', required:true},
  {key:'min_severity', label:'Minimum Severity', type:'select', options:['HIGH','CRITICAL','MEDIUM','LOW'], required:false},
  {key:'max_findings', label:'Max Findings per Sync (blank = all)', type:'number', placeholder:'all', required:false},
  {key:'internal_domains', label:'Internal domains (apps scanned here are not internet-facing)', type:'text', placeholder:'ad.acme.example, corp.acme.example', required:false},
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
  {key:'pull_vulns', label:'Pull vulnerabilities', type:'checkbox', default:true, required:false},
  {key:'pull_software', label:'Pull software inventory (the console sends it)', type:'checkbox', default:true, required:false},
],
rapid7_cloudsec: [
  {key:'base_url',   label:'InsightCloudSec URL', type:'text', placeholder:'https://us1.cloudsec.insight.rapid7.com', required:true},
  {key:'api_key',    label:'InsightCloudSec API Key (not a Command Platform key)', type:'password', placeholder:'', required:true},
  {key:'min_severity', label:'Minimum Insight Severity', type:'select', options:['high','critical','medium','low'], required:false},
  {key:'max_insights', label:'Max Insights per Sync (blank = all)', type:'number', placeholder:'all', required:false},
  {key:'max_findings', label:'Max Findings per Sync (blank = all)', type:'number', placeholder:'all', required:false},
],
tanium: [
  {key:'api_url',    label:'API URL', type:'text', placeholder:'https://<tenant>-api.cloud.tanium.com', required:true},
  {key:'api_token',  label:'API token (read-only role; add this server to its trusted IP addresses)', type:'password', placeholder:'', required:true},
  {key:'pull_vulns', label:'Pull vulnerabilities (Tanium Comply, with proof)', type:'checkbox', default:true, required:false},
  {key:'pull_software', label:'Pull software inventory', type:'checkbox', default:true, required:false},
  {key:'pull_disk_encryption', label:'Pull disk encryption (BitLocker)', type:'checkbox', default:true, required:false},
  {key:'pull_processes', label:'Pull running processes (finds AI agents on endpoints; needs read access to the Running Processes sensor)', type:'checkbox', default:false, required:false},
],
});
