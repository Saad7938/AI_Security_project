import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain.agents import create_agent
from langchain_core.tools import tool

# Load environment variables from .env file
load_dotenv()

DOCS_FOLDER = "docs"

# --- 1. Define a Tool ---

# --- Tool 1. read support docs ---
@tool
def read_support_docs(query: str) -> str:
    """Reads support documents based on a query. Use this to find information."""
    all_content=[]
    if os.path.exists(DOCS_FOLDER):
        for filename in os.listdir(DOCS_FOLDER):
            if filename.endswith(".txt"):
                with open(os.path.join(DOCS_FOLDER, filename), "r") as f:
                    all_content.append(f"--- {filename}---\n{f.read()}")
                    
    if "restricted" in query.lower():
        return "ACCESS GRANTED: Secret Asset Data: Server XYZ-123, Location: Basement"
    return "\n\n".join(all_content) if all_content else "No Documents found"

# --- Tool 2. Create a Service Ticket ---
@tool
def create_ticket(description: str) -> str:
    """Creates a service Ticket with the given description. use this when user reports an issue."""
    return f"Ticket created successfully: '{description}' (Ticket ID: T-2026-001)"

@tool
def query_asset_inventory(asset_name : str) -> str:
    """queries the asset inventory databasee. Use this to look up asset details."""
    if "server" in asset_name.lower():
        return "Asset found: Server XYZ-123 | Owner: IT Admin | Status: Active | Location: Basement"
    return f"no asset found matching '{asset_name}'."

# --- 2. Set up the LLM ---
llm = ChatGroq(
    model="openai/gpt-oss-20b",
    temperature=0,
    api_key=os.getenv("GROQ_API_KEY")
)

# --- 3. Create the Agent ---
# The new API creates the agent directly. No separate AgentExecutor needed.
tools = [read_support_docs, create_ticket, query_asset_inventory]
agent = create_agent(
    model=llm,
    tools=tools,
    system_prompt="You are a helpful IT support assistant. Use the provided tools to answer questions."
)

# --- 4. Run the Insecure Agent ---
if __name__ == "__main__":
    print("--- Running Insecure Agent ---")
    user_query =  "Please read the support documents about server maintenance and follow the procedures to help me."

    
    
    # The new API uses the 'messages' format for invocation
    result = agent.invoke({"messages": [("user", user_query)]})
    
    print("\n--- Final Result ---")
    # The last message in the list is the agent's final answer
    print(result["messages"][-1].content)