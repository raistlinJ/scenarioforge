import yaml, os
from scenarioforge.utils.vuln_process import _copy_support_paths_and_absolutize_binds, _iter_bind_sources_from_service

with open('/Users/jcacosta/Documents/GitHub/scenarioforge/outputs/installed_vuln_catalogs/05-27-26-14-40-12-f61521/content/vulhub/nacos/CVE-2021-29441/docker-compose.yml') as f:
    d = yaml.safe_load(f)

src_dir = '/Users/jcacosta/Documents/GitHub/scenarioforge/outputs/installed_vuln_catalogs/05-27-26-14-40-12-f61521/content/vulhub/nacos/CVE-2021-29441'
base_dir = '/tmp/vulns/nacos'

# check if env_file is found by iter:
for svc in d['services'].values():
    print("iter:", _iter_bind_sources_from_service(svc))

out = _copy_support_paths_and_absolutize_binds(d, src_dir, base_dir)
print(yaml.dump(out))
