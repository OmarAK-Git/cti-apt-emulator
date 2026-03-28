# Automated Threat Intelligence Pipeline (APT Emulation)
> Agent-based pipeline that transforms raw threat intelligence into ATT&CK-aligned, red-team-ready emulation profiles
This project builds an **agent-driven threat intelligence pipeline** that ingests real-world CTI reports and produces structured, **MITRE ATT&CK-aligned threat profiles** for red team emulation.

Instead of manually reading reports, extracting TTPs, and mapping them to ATT&CK, this system automates the process using **multi-agent orchestration (CrewAI)** with strict grounding and validation rules.


## What It Does

Given a set of threat intelligence reports (PDFs):

- Discovers relevant reports  
- Parses and summarizes each source independently (**parallel agents**)  
- Extracts only **concrete, evidence-backed observations**  
- Maps behaviors to **MITRE ATT&CK techniques**  
- Generates a structured **threat profile report**  


## Architecture


            ┌──────────────────────┐
            │   Threat Intel PDFs  │
            └─────────┬────────────┘
                      │
        ┌─────────────▼─────────────┐
        │  Phase 1: Discovery Agent │
        └─────────────┬─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │ Phase 2: Parallel Readers │
        │ (1 agent per PDF)         │
        └─────────────┬─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │ Phase 3: Extraction Agent │
        └─────────────┬─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │  ATT&CK Mapping Agent     │
        └─────────────┬─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │  Report Aggregator        │
        └───────────────────────────┘



## Key Design Decisions

### 1. Parallel Context Isolation

Each PDF is processed independently to avoid:

- context overflow  
- cross-source contamination  
- hallucinated correlations  


### 2. Grounded Extraction (No Inference)

Agents are explicitly instructed to:

- Extract only **explicitly stated behaviors**  
- Avoid assumptions or inferred techniques  
- Prefer omission over weak or ambiguous findings  


### 3. ATT&CK Mapping Discipline

Mappings must:

- Be directly tied to an observed behavior  
- Use valid MITRE ATT&CK technique IDs and names  
- Avoid forcing mappings when evidence is weak  


### 4. Separation of Responsibilities

Each agent has a **single focused role**:

| Agent | Responsibility |
|------|--------|
| Reader | Summarize one source |
| Analyst | Extract technical observations |
| Mapper | Map to MITRE ATT&CK |
| Aggregator | Generate final report |


## Example Output

The pipeline produces a structured threat profile including:

- Executive Summary  
- Threat Actor Background  
- Key Capabilities  
- Tools & Malware  
- MITRE ATT&CK Mapping Table  
- Red Team Emulation Indicators  


## Sample:

- generated threat profile for APT29: [View Sample Report](outputs/apt29_threat_profile.md)


## Why This Project Matters

Most “AI threat intel” demos:

- summarize blogs  
- hallucinate mappings  
- mix sources without validation  

This project focuses on:

- ✅ Grounded intelligence only  
- ✅ Separation of evidence vs assumption  
- ✅ Operational usefulness (red team ready)  
- ✅ Agent-based architecture (not just prompts)  


## Current Limitations

- No automated source quality scoring (yet)  
- No cross-source corroboration layer  
- No ATT&CK validation against official dataset  
- PDF-only ingestion (no live intel feeds)  


## Next Steps (Planned)

- Tavily integration for live threat discovery  
- Source trust scoring system  
- ATT&CK matrix validator  
- IOC normalization & export  
- SIEM detection rule generation  


## How to Run

```bash
pip install -r requirements.txt
python main.py
```

### First Run Behavior

- The first run will create a folder:  
  /threat-intel/<APT_NAME>/  
- The program will exit after creating the folder  
- Add your PDF reports into that folder  
- Run the script again  
- The generated APT emulation report will be saved in the same directory  


### Configuration

- Add your preferred LLM API key to a .env file  
- Choose your model in the get_llm() function  
- Change the target APT via the THREAT_ACTOR variable


### Notes:
- Processing PDFs can be token intensive  
- Use a lighter model for extraction  
- Use a stronger model for analysis  
- CrewAI allows selecting different models per agent, which enables this optimization

##  Acknowledgements

Inspired by the adversary emulation methodology presented in the SANS SEC565 workshop by [Jean-François Maes](https://jfmaes.me)



