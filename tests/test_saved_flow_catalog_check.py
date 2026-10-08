import json
import subprocess
from pathlib import Path


def test_saved_assignment_catalog_uses_explicit_kind_and_unique_legacy_match():
    template = (Path(__file__).resolve().parents[1] / 'webapp/templates/flow.html').read_text()
    start = template.index('  function savedFlowAssignmentCatalog(')
    end = template.index('  async function promptToRemoveUnavailableSavedFlowGenerators', start)
    code = template[start:end] + '''
const enabled = {flag_generators: new Set(['shared','regular']), flag_node_generators: new Set(['131','shared'])};
const results = [
  savedFlowAssignmentCatalog({id:'131'}, enabled),
  savedFlowAssignmentCatalog({id:'131', assignment_type:'flag-node-generator'}, enabled),
  savedFlowAssignmentCatalog({id:'131', type:'flag-generator'}, enabled),
  savedFlowAssignmentCatalog({id:'131', generator_catalog:'flag_node_generators', type:'flag-generator'}, enabled),
  savedFlowAssignmentCatalog({id:'shared'}, enabled),
  savedFlowAssignmentCatalog({id:'absent'}, enabled),
];
console.log(JSON.stringify(results));
'''
    result = subprocess.run(['node', '-e', code], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == ['flag_node_generators', 'flag_node_generators',
        'flag_generators', 'flag_node_generators', None, None]


def test_enabled_legacy_node_assignment_does_not_offer_to_clear_sequence():
    template = (Path(__file__).resolve().parents[1] / 'webapp/templates/flow.html').read_text()
    start = template.index('  function savedFlowAssignmentCatalog(')
    end = template.index('  function compileStringOrRegex(', start)
    code = """
const saved={flag_assignments:[{id:'131'}],chain:[{id:'docker-1'}]};
const before=JSON.stringify(saved);
const _flagGeneratorsCatalog=[];
const _flagNodeGeneratorsCatalog=[{id:'131'}];
let staleSavedFlowGeneratorPrompted=false;
let confirmations=0;
let messages=[];
const window={confirm:()=>{confirmations++;return false;}};
function getFlowStateForScenario(){return saved;}
function setStatus(message){messages.push(message);}
""" + template[start:end] + """
(async()=>{
 await promptToRemoveUnavailableSavedFlowGenerators('demo');
 const preserved=JSON.stringify(saved)===before;
 console.log(JSON.stringify({confirmations,messages,preserved}));
})().catch(error=>{console.error(error);process.exit(1);});
"""
    result = subprocess.run(['node', '-e', code], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == dict(confirmations=0,messages=[],preserved=True)
