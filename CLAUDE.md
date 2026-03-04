# GhidraAgent — Claude Code Notes

## Directory Layout

| Path | Purpose |
|------|---------|
| `../ghidra` | Ghidra source code |
| `../ghidra_llm/ghidra_12.1_DEV` | Installed (compiled) Ghidra — use this for builds and installs |

## Building

Use Ghidra's bundled `gradlew` (not a system `gradle`):

```
/Users/eugenevm/VibeCoding/ghidra_llm/ghidra_12.1_DEV/support/gradle/gradlew \
  -PGHIDRA_INSTALL_DIR=/Users/eugenevm/VibeCoding/ghidra_llm/ghidra_12.1_DEV \
  buildExtension
```

Output: `dist/ghidra_12.1_DEV_<date>_GhidraAgent.zip`

## Installing the Extension

**Correct location:** `~/Library/ghidra/ghidra_12.1_DEV/Extensions/GhidraAgent/`

Only the JAR needs to be replaced on updates:

```
unzip -o dist/ghidra_12.1_DEV_*_GhidraAgent.zip -d /tmp/ghidra_agent_tmp
cp /tmp/ghidra_agent_tmp/GhidraAgent/lib/GhidraAgent.jar \
   ~/Library/ghidra/ghidra_12.1_DEV/Extensions/GhidraAgent/lib/
rm -rf /tmp/ghidra_agent_tmp
```

**Do NOT install into** `ghidra_llm/ghidra_12.1_DEV/Ghidra/Extensions/` — this creates a
duplicate module that prevents Ghidra from starting.
