#snort
!228 ar.conf
restart-ossec0 - restart-ossec.sh - 0
restart-ossec0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-ossec.sh - 0
restart-wazuh0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-wazuh - 0
restart-wazuh0 - restart-wazuh.exe - 0
!159 agent.conf
  <agent_config>
    <localfile>
      <log_format>json</log_format>
      <location>/home/mike/snort/flows.json</location>
    </localfile>
  </agent_config>
