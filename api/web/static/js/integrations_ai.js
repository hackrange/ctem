// Integrations page: the AI / LLM providers. Loaded before the page script, which spreads AI_VENDOR_FIELDS
// into VENDOR_FIELDS. Fields inside a [hidden] wrapper are skipped when the form is saved.
const AI_VENDOR_META = [
  { slug: 'anthropic', label: 'Claude (Anthropic)' },
  { slug: 'bedrock',   label: 'Claude on Amazon Bedrock' },
  { slug: 'openai',    label: 'OpenAI' },
  { slug: 'custom_ai', label: 'Custom AI / LLM' },
];
const AI_VENDORS = new Set(['anthropic', 'bedrock', 'openai', 'custom_ai', 'ai']);

const BEDROCK_REGIONS = ['us-east-1', 'us-east-2', 'us-west-2', 'us-gov-west-1', 'ca-central-1', 'eu-west-1',
  'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-south-1'];
const BEDROCK_MODELS = ['anthropic.claude-opus-5-5', 'anthropic.claude-sonnet-5-5', 'anthropic.claude-haiku-5-5',
  'anthropic.claude-fable-5-2', 'anthropic.claude-opus-5', 'anthropic.claude-sonnet-5'];

const AI_VENDOR_FIELDS = {
  anthropic: [
    {key:'base_url',   label:'API Base URL',    type:'text',     placeholder:'https://api.anthropic.com', default:'https://api.anthropic.com', required:true, readonly:true},
    {key:'api_key',    label:'API Key',         type:'password', placeholder:'sk-ant-...', required:true},
    {key:'model',      label:'Default Model',   type:'model_select', vendor:'anthropic', required:false,
      options:['claude-opus-5-5','claude-sonnet-5-5','claude-haiku-5-5','claude-fable-5-2','claude-opus-5','claude-sonnet-5','claude-haiku-4-5','claude-sonnet-4-6']},
  ],
  bedrock: [
    {key:'aws_region', label:'AWS Region',      type:'select', options:BEDROCK_REGIONS, required:true},
    {key:'auth_mode',  label:'Sign in with',    type:'select', options:['access_key', 'api_key', 'default'], required:true,
      optionLabels:{access_key:'IAM access key', api_key:'Bedrock API key', default:"This server's AWS credentials (IAM role)"}},
    {key:'aws_access_key_id',     label:'Access Key ID',     type:'text',     placeholder:'AKIA...', required:true, auth:'access_key'},
    {key:'aws_secret_access_key', label:'Secret Access Key', type:'password', placeholder:'', required:true, auth:'access_key'},
    {key:'api_key',    label:'Bedrock API Key', type:'password', placeholder:'', required:true, auth:'api_key'},
    {key:'model',      label:'Default Model',   type:'select', options:BEDROCK_MODELS, required:false},
  ],
  openai: [
    {key:'base_url',   label:'API Base URL',    type:'text',     placeholder:'https://api.openai.com', default:'https://api.openai.com', required:true, readonly:true},
    {key:'api_key',    label:'API Key',         type:'password', placeholder:'sk-...', required:true},
    {key:'model',      label:'Default Model',   type:'model_select', vendor:'openai', required:false,
      options:['gpt-4o','gpt-4o-mini','o1','o1-mini','o3-mini','gpt-4-turbo','gpt-3.5-turbo']},
  ],
  custom_ai: [
    {key:'base_url',   label:'API Base URL',    type:'text',     placeholder:'https://your-llm-provider.example.com', required:true},
    {key:'api_key',    label:'API Key',         type:'password', placeholder:'', required:false},
    {key:'model',      label:'Default Model',   type:'text',     placeholder:'', required:false},
    {key:'extra_headers', label:'Extra Headers (JSON; may hold credentials, stored like a secret)',type:'secret_text', placeholder:'{"X-Custom": "value"}', required:false},
  ],
};

// Show only the credential fields the chosen Bedrock sign-in needs. Called after the fields render or fill.
function aiFieldsShown(vendor) {
  if (vendor !== 'bedrock') return;
  const mode = document.getElementById('cfg-auth_mode');
  if (!mode) return;
  const apply = () => {
    for (const f of AI_VENDOR_FIELDS.bedrock) {
      const el = f.auth && document.getElementById(`cfg-${f.key}`);
      if (el) el.parentElement.hidden = f.auth !== mode.value;
    }
  };
  mode.onchange = apply;
  apply();
}
