import os
import asyncio
from typing import List
from pydantic import BaseModel
from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools import BaseTool
from crewai.flow.flow import Flow, listen, start
from crewai_tools import DirectoryReadTool
from pypdf import PdfReader
from dotenv import load_dotenv
load_dotenv()

THREAT_ACTOR = "APT29"
REPORT_PREFIX = THREAT_ACTOR.lower().replace(" ", "_")

# ============================================================
# LLM Configuration — auto-detects your provider
# ============================================================
def get_llm():
    if os.getenv("LITELLM_API_BASE"):
        return LLM(
            model=os.getenv("MODEL_NAME", "openai/gpt-4o"),
            base_url=os.getenv("LITELLM_API_BASE"),
            api_key=os.getenv("LITELLM_API_KEY")
        )
    elif os.getenv("ANTHROPIC_API_KEY"):
        return LLM(model="anthropic/claude-sonnet-4-5-20250929")
    elif os.getenv("GROQ_API_KEY"):
        return LLM(model="groq/llama-3.3-70b-versatile")
    elif os.getenv("OPENAI_API_KEY"):
        return LLM(model="openai/gpt-4o-mini")
    else:
        return LLM(model="ollama/llama3.2")


llm = get_llm()


# ============================================================
# Custom PDF Reader Tool
# CrewAI's built-in FileReadTool doesn't handle PDFs,
# so we build our own using pypdf
# ============================================================
class PDFReaderTool(BaseTool):
    name: str = "Read PDF file"
    description: str = "Reads and extracts text from a PDF file. Input: the full file path."

    def _run(self, file_path: str) -> str:
        try:
            reader = PdfReader(file_path.strip())
            text = ""
            for i, page in enumerate(reader.pages):
                try:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
                except Exception as page_error:
                    text += f"\n[Page {i + 1} could not be extracted]\n"
            return text if text.strip() else "No text could be extracted from PDF"
        except Exception as e:
            return f"Error reading PDF: {str(e)}"


# ============================================================
# Flow State — the shared notebook between phases
# ============================================================
class ThreatIntelState(BaseModel):
    pdf_paths: List[str] = []
    pdf_summaries: List[str] = []
    combined_summaries: str = ""
    final_report: str = ""


# ============================================================
# The Flow — three phases, wired together
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
THREAT_INTEL_DIR = os.path.join(BASE_DIR, "threat-intel", REPORT_PREFIX)

os.makedirs(THREAT_INTEL_DIR, exist_ok=True)

if not os.listdir(THREAT_INTEL_DIR):
    print(f"[INFO] Folder ready: {THREAT_INTEL_DIR}")
    print("[INFO] Add PDF files and run again.")
    exit()


class ThreatIntelFlow(Flow[ThreatIntelState]):

    @start()
    def discover_files(self):
        """PHASE 1: Find PDF files in the threat-intel directory."""
        print("=" * 60)
        print("PHASE 1: Discovering threat intelligence files...")
        print("=" * 60)

        directory_tool = DirectoryReadTool(directory=THREAT_INTEL_DIR)

        discovery_agent = Agent(
            role="File Discovery Specialist",
            goal="List all PDF files in the threat-intel directory",
            backstory="You identify relevant files for analysis.",
            tools=[directory_tool],
            llm=llm,
            verbose=False
        )

        discovery_task = Task(
            description=f"""List all files in the directory: {THREAT_INTEL_DIR}
            Return ONLY the full paths of PDF files related to {THREAT_ACTOR} threat intelligence.
            Return as a simple list, one path per line.""",
            expected_output="A list of PDF file paths, one per line",
            agent=discovery_agent
        )

        discovery_crew = Crew(
            agents=[discovery_agent],
            tasks=[discovery_task],
            process=Process.sequential,
            verbose=False
        )

        result = discovery_crew.kickoff()

        # Parse discovered paths
        pdf_paths = [
            line.strip()
            for line in str(result).strip().split('\n')
            if line.strip().lower().endswith('.pdf')
        ]

        # Fallback to known filenames
        if not pdf_paths:
            pdf_paths = [
                os.path.join(THREAT_INTEL_DIR, f)
                for f in os.listdir(THREAT_INTEL_DIR)
                if f.lower().endswith(".pdf")
            ]

        self.state.pdf_paths = pdf_paths
        print(f"\nDiscovered {len(pdf_paths)} PDF files")

    @listen(discover_files)
    async def read_pdfs_parallel(self):
        """PHASE 2: Read all PDFs in parallel, each with fresh context."""
        print("\n" + "=" * 60)
        print("PHASE 2: Reading PDFs in parallel...")
        print("=" * 60)

        pdf_tool = PDFReaderTool()

        def create_pdf_crew(pdf_path):
            scout = Agent(
                role="Threat Intelligence Researcher",
                goal="Read and summarize a single threat intelligence PDF report",
                backstory="""You are a threat intelligence researcher specializing in APT groups.
                You read a single PDF report and extract key findings about TTPs, tools, and techniques.
                Focus on technical details and documented behaviors.""",
                tools=[pdf_tool],
                llm=llm,
                verbose=False
            )

            read_task = Task(
                description=f"""Read the PDF file at: {pdf_path}

                Summarize only the technical findings explicitly described in this report.
                
                Extract:
                - Victim targets and operational objectives
                - Initial access methods
                - Malware, tools, and scripts used
                - Persistence methods
                - Credential access techniques
                - Lateral movement or privilege escalation
                - Command and control behavior
                - Data collection and exfiltration methods
                - Notable infrastructure, file paths, registry keys, or artifacts
                
                Rules:
                - Do not add outside knowledge
                - Do not infer techniques unless strongly supported by the report
                - Prefer concrete observations over broad background
                - Keep the summary concise and technical
                - If the report does not mention something, omit it""",
                expected_output="A concise summary of TTPs from this report",
                agent=scout
            )

            return Crew(
                agents=[scout],
                tasks=[read_task],
                process=Process.sequential,
                verbose=False,
                memory=False
            )

        # Run all PDF crews in parallel
        tasks = []
        for pdf_path in self.state.pdf_paths:
            crew = create_pdf_crew(pdf_path)
            tasks.append(crew.kickoff_async(inputs={}))
        reading_results = await asyncio.gather(*tasks)

        self.state.pdf_summaries = [str(result) for result in reading_results]
        self.state.combined_summaries = "\n\n---\n\n".join([
            f"## {self.state.pdf_paths[i]}\n{summary}"
            for i, summary in enumerate(self.state.pdf_summaries)
        ])

        print("\nPHASE 2 COMPLETE: All summaries stored")

    @listen(read_pdfs_parallel)
    def analyze_and_map(self):
        """PHASE 3: Multi-agent analysis — extract, map, report."""
        print("\n" + "=" * 60)
        print("PHASE 3: Multi-agent analysis...")
        print("=" * 60)

        # Agent 1: Pull out technical details
        analyst = Agent(
            role="Technical Intelligence Extractor",
            goal="Extract technical indicators and behaviors from threat intelligence summaries",
            backstory="""You are a technical analyst who extracts actionable intelligence:
            tools used, file paths, registry keys, and specific behaviors.
            You ignore attribution speculation and focus on technical facts.""",
            llm=llm,
            verbose=False
        )

        # Agent 2: Map to ATT&CK
        mapper = Agent(
            role="MITRE ATT&CK Mapping Specialist",
            goal="Map threat behaviors to MITRE ATT&CK technique IDs",
            backstory="""You are a CTI specialist with deep knowledge of MITRE ATT&CK.
            You take observations like 'Used Procdump to dump LSASS' and map them to
            technique IDs like T1003.001.""",
            llm=llm,
            verbose=False
        )

        # Agent 3: Write the final report
        aggregator = Agent(
            role="Threat Intelligence Report Writer",
            goal="Compile all analysis into a comprehensive Threat Profile",
            backstory="""You are a senior threat intelligence analyst who creates actionable
            reports for Red Team engagements.""",
            llm=LLM(model="openai/gpt-5.4"),
            verbose=False
        )

        extraction_task = Task(
            description="""From these summaries, extract only concrete technical observations 
            explicitly supported by the source summaries.
            
            {summaries}
            
            Output rules:
            - One observation per bullet
            - Prefer specific tools, malware, behaviors, infrastructure, artifacts, and attack actions
            - Exclude broad attribution/background statements unless operationally useful
            - Exclude duplicate observations
            - Keep each bullet short and precise""",
            expected_output="A bulleted list of technical observations",
            agent=analyst
        )

        mapping_task = Task(
            description="""Map the extracted observations to MITRE ATT&CK Enterprise techniques.
            
            Only map observations that describe a clear attacker behavior or action.
            Do not map raw artifacts alone (file names, hashes, domains, malware names, or lure names) unless the behavior they support is explicitly stated.
            Do not force a mapping if the evidence is weak, ambiguous, or indirect.
            
            Rules:
            - Use only valid ATT&CK Enterprise tactic names and technique IDs
            - Prefer the most specific sub-technique only when clearly justified by the observation
            - If the observation is broad, choose a broader valid technique or omit it
            - Do not infer lateral movement, exfiltration, persistence, or credential access unless the summaries explicitly support it
            - Base mappings only on the extracted observations, not on general knowledge of the threat actor
            - Technique Name must exactly match official MITRE ATT&CK naming
            - Do not map generic malware listings, tool names, or artifact lists to ATT&CK techniques unless a specific behavior is explicitly described
            - Do not include duplicate mappings unless they represent distinct behaviors
            - Do not map observations that only describe the presence or use of malware, tools, or frameworks without a clearly described action
            - Technique ID and Technique Name must correspond exactly to each other as defined in MITRE ATT&CK
            - Only use sub-techniques (e.g., T1003.001) if the specific mechanism is explicitly described in the observation; otherwise use the parent technique or omit
            
            Valid ATT&CK Enterprise tactics are:
            Reconnaissance
            Resource Development
            Initial Access
            Execution
            Persistence
            Privilege Escalation
            Defense Evasion
            Credential Access
            Discovery
            Lateral Movement
            Collection
            Command and Control
            Exfiltration
            Impact
            
            Output format:
            | Observation | Technique ID | Technique Name | Tactic | Rationale |
            
            Requirements:
            - Include only high-confidence mappings
            - Return fewer than 8 mappings if fewer than 8 are well supported
            - Each rationale must cite the specific behavior in the observation that supports the mapping""",
            expected_output="A markdown table mapping observations to ATT&CK techniques",
            agent=mapper,
            context=[extraction_task]
        )

        aggregation_task = Task(
            description=f"""Create a COMPLETE {THREAT_ACTOR} Threat Profile Report using 
            only the extracted observations and ATT&CK mappings provided in context.
            Write in a concise analyst style, not a marketing or encyclopedia tone.
            Requirements:
            1. Executive Summary
               - 1-2 short paragraphs
               - Summarize the actor’s operational patterns observed in the provided source set
            2. Threat Actor Background
               - Keep brief
               - Include aliases, victimology, and campaign context only if supported by the source set or clearly established
            3. Key Capabilities Summary
               - Focus on observed behaviors from the current reports
            4. Tools and Malware
               - List only tools, malware, and frameworks supported by the source material
            5. MITRE ATT&CK TTP Mapping Table
               - Use the validated mapping table from context
            6. Indicators for Red Team Emulation
               - Focus on actionable attack chain elements, infrastructure patterns, and detection opportunities
            
            Rules:
            - Do not pad the report with generic threat actor history
            - Distinguish observed-in-source behavior from general background
            - Be concise, technical, and operationally useful
            - Avoid repeating the same finding in multiple sections""",
            expected_output="A complete markdown Threat Profile Report with all 6 sections",
            agent=aggregator,
            context=[extraction_task, mapping_task]
        )

        analysis_crew = Crew(
            agents=[analyst, mapper, aggregator],
            tasks=[extraction_task, mapping_task, aggregation_task],
            process=Process.sequential,
            verbose=True
        )

        result = analysis_crew.kickoff(inputs={"summaries": self.state.combined_summaries})
        self.state.final_report = str(result.raw)

        #print("\n" + "=" * 60)
        #print(f"FINAL {THREAT_ACTOR} THREAT PROFILE REPORT")
        #print("=" * 60)
        #print(self.state.final_report)

        REPORT_PATH = os.path.join(THREAT_INTEL_DIR, f"{REPORT_PREFIX}_threat_profile.md")

        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            f.write(f"# {THREAT_ACTOR} Threat Profile\n\n")
            f.write("*Generated by CrewAI Threat Intelligence Flow*\n\n")
            f.write(self.state.final_report)
        print(f"\n[Report saved to {REPORT_PATH}")
        os.startfile(REPORT_PATH)

        return self.state.final_report


if __name__ == "__main__":
    flow = ThreatIntelFlow()
    result = flow.kickoff()
    print("\n" + "=" * 60)
    print("FLOW COMPLETE")
    print("=" * 60)