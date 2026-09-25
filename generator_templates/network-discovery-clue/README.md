# Network discovery clue

Import this directory through the usual generator catalog workflow, then assign it
to an appropriate vulnerability node. Set internal_subnet to the actual deployed
internal network; the generator does not create routes, interfaces, or a pivot.
It emits InternalNetwork(subnet) for downstream fact matching and a deterministic
network.conf file for injection into /opt/scenario. The file contains the subnet
and this challenge's flag. Access to that file comes from the host's challenge.

Use docs/examples/evaluation-discovery-tasks.json as the evaluation task contract,
replacing graph IDs, addresses, and evidence paths to match your saved scenario.
Verify the injection and route in the deployed environment before exporting.
Do not copy generator outputs or facilitator guides into participant starting facts.

The evaluator stores evidence provenance but does not infer that a file was read
from flag recovery, nor does this template install itself into the catalog.
