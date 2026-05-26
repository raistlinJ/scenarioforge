# ScenarioForge Screenshots

Preview the major pages of the Web UI to get a feel for the workflow before running the app.

<div align="center">
	<img src="images/system-architecture.png" alt="Conceptual ScenarioForge system architecture" width="900" />
	<p><em>Conceptual architecture across frontend, backend, Proxmox, and the CORE VM.</em></p>
	<img src="images/flag-sequencing.png" alt="Flag sequencing challenge flow visualization" width="720" />
	<p><em>Flag Sequencing view with generated challenge dependencies.</em></p>
	<img src="images/full-preview.png" alt="Full Preview modal with topology graph" width="720" />
	<p><em>Full Preview graph with routers, hosts, switches, vulnerabilities, and HITL details.</em></p>
	<img src="images/reports-downloads.png" alt="Reports history table with downloads menu" width="720" />
	<p><em>Reports history with downloadable run artifacts.</em></p>
	<img src="images/facilitator-guide.png" alt="Facilitator guide challenge sequence" width="720" />
	<p><em>Facilitator guide export with the challenge sequence and step checklist.</em></p>
</div>

## Execute retry prompt checklist

When capturing or reviewing screenshots for the Execute retry flow, verify these UI states:

- Execute confirmation is shown before launch.
- Run fails due to active session(s) and shows the prompt title: `Active CORE session(s) blocked this run`.
- Prompt includes a clear confirm action: `Retry with cleanup`.
- After confirm, a new run is launched (new run id in logs/progress) instead of staying on the failed run.
- Retry happens once (no infinite prompt/retry loop).
