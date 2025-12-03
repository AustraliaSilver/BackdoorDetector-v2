package backdoordetected.services;

import java.util.ArrayList;
import java.util.List;
public class AIPromptBuilder {
  private List<String> suspiciousFiles = new ArrayList<>();
  private String findings = "";
  private String code = "";
  private String directoryTree = "";
  private boolean hasKnownBackdoor = false;

  public AIPromptBuilder withSuspiciousFiles(List<String> files) {
    this.suspiciousFiles = files != null ? new ArrayList<>(files) : new ArrayList<>();
    return this;
  }

  public AIPromptBuilder withFindings(String findings) {
    this.findings = findings != null ? findings : "";
    return this;
  }

  public AIPromptBuilder withCode(String code) {
    this.code = code != null ? code : "";
    return this;
  }

  public AIPromptBuilder withDirectoryTree(String tree) {
    this.directoryTree = tree != null ? tree : "";
    return this;
  }

  public AIPromptBuilder withKnownBackdoorDetected(boolean detected) {
    this.hasKnownBackdoor = detected;
    return this;
  }

  public String build() {
    String fileList = suspiciousFiles.isEmpty() ? "N/A" : String.join(", ", suspiciousFiles);

    return String.format(
        """
                        You are a world-class Minecraft plugin security expert. Your **only mission** is to determine if this plugin contains a **hidden, malicious backdoor**. You must be extremely precise and avoid false positives.

                        **CRITICAL INSTRUCTIONS:**
                        0.  **KNOWN BACKDOOR SIGNATURES (AUTO-DETECT):** If you see these patterns in INITIAL FINDINGS, they are **100%% confirmed backdoors**:
                            *   **L.M.X backdoor**: Sequential L/M/X directory structure - this is a well-known malware signature
                            *   **OpenEctasy malware**: 'bodyalhoha' directory - this is a confirmed malware pattern
                            *   If either is detected, report as **Malicious: YES, Confidence: 100%%, Severity: CRITICAL**

                        1.  **PRIMARY GOAL: FIND TRUE BACKDOORS.** A true backdoor is **deceptive and hidden**. Prioritize finding these:
                            *   Is triggered by a **secret, non-obvious action** (e.g., a specific chat message, a hardcoded player name/UUID, joining at a specific time).
                            *   Communicates with **suspicious, hardcoded external servers** (e.g., pastebin, discord webhooks, random IPs) to fetch commands or exfiltrate data.
                            *   Uses **heavy obfuscation** (e.g., decoding strings from Base64/Hex/byte arrays) specifically to hide malicious intent.

                        2.  **SECONDARY GOAL: IDENTIFY CONFIGURABLE FEATURES THAT CAN BE ABUSED.** These are **NOT backdoors**, but are worth noting.
                            *   A feature is **NOT a backdoor** if it requires a server administrator to edit a file (`.yml`, `.json`, etc.) in the plugin's folder.
                            *   **Example:** A plugin that runs commands from `commands.yml` is a feature. It is the admin's responsibility to secure that file. Report this as a "Configuration Vulnerability", not a backdoor.
                            *   **Example:** A plugin that grants OP status based on a value in a data file (like AuthMe's Limbo feature) is a feature. Report this as a "Configuration Vulnerability".
                            *   **Example:** A plugin using `Runtime.exec` for a legitimate purpose like database backups (`mysqldump`) is a feature. Do not flag this unless the command arguments can be controlled by a non-admin.

                        3.  **IGNORE LIBRARY FINDINGS:** The `INITIAL FINDINGS` may contain suspicious calls (like reflection or unreachable code) from bundled libraries (e.g., `io.netty`, `com.zaxxer.hikari`, `org.mariadb`, `com.mysql`, `javax.mail`). These are almost always **FALSE POSITIVES**. Ignore them unless there is direct evidence they are being used maliciously by the plugin's own code.

                        ### SOURCE CODE & CONTEXT
                        %s
                        Directory Tree: %s
                        SUSPICIOUS FILES: %s
                        INITIAL FINDINGS:
                        %s

                        ### YOUR TASK & RESPONSE FORMAT
                        Based on the criteria above, analyze the plugin.
                        **Strictly follow this format.**

                        **Malicious:** [YES/NO] (Only YES if you find a **true backdoor** as defined in rule #1)
                        **Confidence:** [0-100%%]
                        **Severity:** [CRITICAL / HIGH / MEDIUM / LOW / NONE]
                        **Vulnerability Type:** [Hardcoded Backdoor / Command Injection / Remote Code Execution / Malicious Download / Obfuscation / Data Stealing / Configuration Vulnerability / False Positive]

                        ### BRIEF REASONING
                        Provide a concise explanation. If you found a true backdoor, explain it first. If you only found configurable features that can be abused (rule #2), explain that clearly and state that it's not a true backdoor but a configuration risk.
                        """,
        code, directoryTree, fileList, findings);
  }
}
