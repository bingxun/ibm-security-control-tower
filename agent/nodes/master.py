"""Master coordinator: prepare queued CVEs for bounded parallel assessment workers."""
from agent.state import AgentState, AgentStep


def master_node(state: AgentState) -> dict:
    queued = sum(c['status'] == 'queued' for c in state['cves'])
    return {'agent_steps': [*state.get('agent_steps', []), AgentStep(
        id='master', title='Master agent · Coordinate CVE workers',
        desc=f'Dispatch {queued} CVE workers: memory lookup, environment assessment and remediation. Human approval required.',
        chips=[{'label':'master','variant':'tool'}, {'label':f'{queued} slaves','variant':'stream'}],
        state='active' if queued else 'done',
    )]}
