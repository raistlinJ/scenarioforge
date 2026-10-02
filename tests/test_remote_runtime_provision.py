"""The provisioned CORE checkout must match APP remote-execution settings."""
from pathlib import Path
import shlex
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT/'scripts/provision/proxmox/install-scenarioforge-lab.sh'


@pytest.mark.parametrize('existing', [False, True])
def test_core_checkout_is_updated_as_runtime_ssh_user(tmp_path, existing):
    source=INSTALLER.read_text()
    block=source.split("set_bootstrap_status 75 'installing ScenarioForge custom CORE services'\n",1)[1].split('install -d -m 0755 /opt/core/custom_services',1)[0]
    repo=tmp_path/'repo'
    repo.mkdir()
    if existing:(repo/'.git').mkdir()
    block=block.replace('/opt/scenarioforge-services',str(repo))
    result=subprocess.run(['bash','-c',"""
set -eu
SCENARIOFORGE_REF=main
SCENARIOFORGE_URL=https://example.invalid/repo.git
install() { echo "install $*"; }
chown() { echo "chown $*"; }
runuser() { echo "runuser $*"; }
git() { echo 'unexpected root git'; exit 77; }
fail_bootstrap() { echo "$*"; exit 1; }
"""+block],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    assert f'chown -R corevm:corevm {repo}' in result.stdout
    commands=[line for line in result.stdout.splitlines() if line.startswith('runuser')]
    assert len(commands)==(3 if existing else 1)
    assert all(line.startswith('runuser -u corevm -- git ') for line in commands)
    assert ('pull --ff-only' in result.stdout)==existing


def test_core_checkout_symlink_is_rejected(tmp_path):
    source=INSTALLER.read_text()
    block=source.split("set_bootstrap_status 75 'installing ScenarioForge custom CORE services'\n",1)[1].split('install -d -m 0755 /opt/core/custom_services',1)[0]
    repo=tmp_path/'repo'
    repo.symlink_to(tmp_path/'elsewhere')
    result=subprocess.run(['bash','-c','set -eu\nfail_bootstrap() { echo "$*"; exit 1; }\n'+block.replace('/opt/scenarioforge-services',str(repo))],
                          capture_output=True,text=True,timeout=10)
    assert result.returncode!=0
    assert 'Refusing a symlink' in result.stdout


def test_app_environment_points_to_provisioned_core_checkout(tmp_path):
    source=INSTALLER.read_text()
    block=source.split('cat > /opt/scenarioforge/.scenarioforge.env <<ENV_FILE\n',1)[1].split('\nENV_FILE',1)[0]
    result=subprocess.run(['bash','-c','cat <<ENV_FILE\n'+block+'\nENV_FILE\n'],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    assert values['CORE_REMOTE_STATIC_REPO']=='/opt/scenarioforge-services'
    assert values['CORE_SSH_USERNAME']=='corevm'
    # VMware guest payloads share this provisioning implementation.
    for name in ('vmware-workstation-linux','vmware-fusion-mac'):
        wrapper=(ROOT/'scripts/provision'/name/'install-scenarioforge-lab.sh').read_text()
        assert 'proxmox/install-scenarioforge-lab.sh' in wrapper or 'vmware-workstation-linux/install-scenarioforge-lab.sh' in wrapper
