import re,os,sys
dirs=[l.split()[1] for l in open('/tmp/p75-pkgmap.txt')]
pat=re.compile(r'(?<![A-Za-z_:])(println|print|eprintln|eprint|dbg)!')
from collections import Counter
c=Counter()
out=[]
for d in dirs:
    for root,ds,fs in os.walk(d):
        ds[:]=[x for x in ds if x not in ('tests','benches','examples','target','testdata','fixtures','test')]
        for f in fs:
            if not f.endswith('.rs') or f.endswith('_tests.rs') or f in('tests.rs','test.rs','test_utils.rs','testkit.rs'): continue
            p=os.path.join(root,f)
            txt=open(p,errors='ignore').read()
            lines=txt.split('\n')
            for i,l in enumerate(lines):
                s=l.strip()
                if s.startswith('#[cfg(test)]'):
                    # find next nonattr line; if mod, stop
                    j=i+1
                    while j<len(lines) and lines[j].strip().startswith('#'): j+=1
                    if j<len(lines) and re.match(r'(pub(\(crate\))? )?mod ',lines[j].strip()): break
                if s.startswith('//'): continue
                if pat.search(l):
                    c[d]+=1; out.append(f'{p}:{i+1}: {s[:120]}')
for k,v in sorted(c.items(), key=lambda x:-x[1]): print(v,k)
open('/tmp/p75-sites.txt','w').write('\n'.join(out))
