"""Validate recorded /v1 responses against openapi.yaml (path + status → schema)."""
import json, re, sys, glob, yaml, jsonschema
from openapi_spec_validator import validate
spec = yaml.safe_load(open(sys.argv[1])); validate(spec)
defs = spec['components']['schemas']
def fix(o):
    if isinstance(o, dict):
        o = {k: fix(v) for k, v in o.items() if k not in ('discriminator', 'example')}
        if '$ref' in o: o['$ref'] = o['$ref'].replace('#/components/schemas/', '#/$defs/')
        return o
    return [fix(x) for x in o] if isinstance(o, list) else o
fdefs = fix(defs)
def path_re(p): return re.compile('^' + re.sub(r'\{[^}]+\}', '[^/?]+', p) + '$')
routes = [(path_re(p), p, ops) for p, ops in spec['paths'].items()]
bad = 0; checked = 0
for f in sorted(glob.glob(sys.argv[2] + '/*.json')):
    r = json.load(open(f)); path = r['path'].split('?')[0]
    if not path.startswith('/v1'): continue  # legacy/admin routes aren't part of the contract
    m = next(((p, ops) for rx, p, ops in routes if rx.match(path)), None)
    if not m:
        # unknown routes must still use the error envelope
        schema = {'$ref': '#/$defs/Error'}; where = '(fallback)'
    else:
        p, ops = m; op = ops.get(r['method'].lower())
        if op is None: print('NO OP', r['method'], path); bad += 1; continue
        resp = op['responses'].get(str(r['status']))
        if resp is None: print('UNDOCUMENTED STATUS', r['status'], r['method'], p); bad += 1; continue
        if '$ref' in resp: resp = spec['components']['responses'][resp['$ref'].split('/')[-1]]
        content = resp.get('content', {}).get('application/json')
        if not content: continue
        schema = fix(content['schema']); where = p
    try:
        jsonschema.Draft202012Validator({**schema, '$defs': fdefs}).validate(r['body']); checked += 1
    except jsonschema.ValidationError as e:
        bad += 1; print('MISMATCH', r['method'], path, r['status'], '-', e.message[:160])
print(f'checked {checked} responses against the spec, {bad} problems')
sys.exit(1 if bad else 0)
