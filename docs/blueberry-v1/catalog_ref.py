"""Reference decoder driven ONLY by findings-catalog.v3lean.json. The Rust SDK port must match this."""
import json, re
C = json.load(open('findings-catalog.v3lean.json'))
def decode(tag):
    return {k: (tag >> off) & ((1 << w) - 1) for k, (off, w) in C['fields'].items()}
def ev(expr, d):
    py = expr.replace('||',' or ').replace('&&',' and ')
    py = re.sub(r'!(?!=)', ' not ', py)
    return bool(eval(py, {'true': True}, d))
def build(tag):
    d = decode(tag)
    fs = []
    for f in C['findings']:
        if not ev(f['when'], d): continue
        title = f['title']
        if '{consolidation_class}' in title: title = title.replace('{consolidation_class}', C['enums']['consolidation_class'][d['consolidation_class']])
        if '{count}' in title:
            n = d['rbf_signaled'] + d['no_locktime'] + d['legacy_version']
            title = f"{n} wallet fingerprinting signal" + ("" if n == 1 else "s")
        fs.append([f['id'], title, f['severity'], f['confidence'], f['description'], f['recommendation']])
    g = d['grade']
    score = C['synthetic_score']['3_deterministic_cap'] if g == 3 and d['deterministic_cap'] else C['synthetic_score'][str(g)]
    rec = next(r for r in C['primary_recommendation_cascade'] if ev(r['when'], d))
    return {'grade': C['display_grade'][str(g)], 'score': score, 'urgency': rec['urgency'], 'headline': rec['headline'], 'detail': rec['detail'], 'findings': fs}
