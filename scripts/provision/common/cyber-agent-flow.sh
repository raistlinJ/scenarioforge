# Shared configuration and guest generation for the optional Kali application.
CAF_HELPER="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/cyber_agent_flow.py"
CYBER_AGENT_FLOW="${SF_CYBER_AGENT_FLOW:-0}"
CYBER_AGENT_FLOW_URL="${SF_CYBER_AGENT_FLOW_URL:-https://github.com/raistlinJ/cyber-agent-flow.git}"
CYBER_AGENT_FLOW_REF="${SF_CYBER_AGENT_FLOW_REF:-main}"
LLM_PROVIDER_ADDRESS="${SF_LLM_PROVIDER_ADDRESS:-}"
LLM_PROVIDER_URL="${SF_LLM_PROVIDER_URL:-}"
LLM_PROVIDER_TYPE="${SF_LLM_PROVIDER_TYPE:-ollama_direct}"
LLM_MODEL="${SF_LLM_MODEL:-}"
LLM_INTERFACE_CIDR="${SF_LLM_INTERFACE_CIDR:-}"
LLM_GATEWAY="${SF_LLM_GATEWAY:-}"
LLM_VMNET="${SF_LLM_VMNET:-vmnet8}"
LLM_BRIDGE="${SF_LLM_BRIDGE:-}"

apply_caf_config() {
    local key="$1" value="$2" variable
    variable="$(printf '%s' "$key" | tr '[:lower:]' '[:upper:]')"
    if [[ "$key" == cyber_agent_flow ]]; then
        parse_config_boolean "$key" "$value"
        value="$CONFIG_BOOLEAN_VALUE"
    fi
    assign_config_setting "$variable" "SF_$variable" "$value"
}

caf_generate() {
    local key variable
    for key in cyber_agent_flow cyber_agent_flow_url cyber_agent_flow_ref llm_provider_address llm_provider_url llm_provider_type llm_model llm_interface_cidr llm_gateway llm_vmnet llm_bridge participant_os participant_cidr core_management_cidr; do
        variable="$(printf '%s' "$key" | tr '[:lower:]' '[:upper:]')"
        export "SF_CAF_$variable=${!variable}"
    done
    python3 "$CAF_HELPER" "$@"
}

validate_caf() {
    [[ "$CYBER_AGENT_FLOW" == 0 || "$CYBER_AGENT_FLOW" == 1 ]] || die 'cyber_agent_flow must be true or false'
    [[ "$CYBER_AGENT_FLOW" == 1 ]] || return 0
    caf_generate validate || die 'invalid CyberAgentFlow / LLM network configuration'
}

save_caf_state() {
    local variable
    for variable in CYBER_AGENT_FLOW CYBER_AGENT_FLOW_URL CYBER_AGENT_FLOW_REF LLM_PROVIDER_ADDRESS LLM_PROVIDER_URL LLM_PROVIDER_TYPE LLM_MODEL LLM_INTERFACE_CIDR LLM_GATEWAY LLM_VMNET LLM_BRIDGE; do
        shell_assignment "$variable" "${!variable}"
    done
}
