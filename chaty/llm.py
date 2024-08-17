from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import OpenAI
from langchain_anthropic import ChatAnthropic
from langchain.memory import ConversationBufferMemory
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_groq import ChatGroq
from dotenv import load_dotenv
import os

load_dotenv()

lc_key = os.getenv('lc_key')

# Setup LANGSMITH for LLMOps :
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = "audiosmith"
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
os.environ["LANGCHAIN_API_KEY"] = lc_key

load_dotenv()  # Load environment variables from .env file


def LLMChain(model_name: str, query: str) -> str:
    """
    Creates a LangChain chain with the specified LLM and processes the query.

    Args:
        model_name (str): The name of the LLM to use (e.g., "gpt-3.5-turbo").
        query (str): The user's query to process.

    Returns:
        str: The LLM's response to the query.
    """

    # 1. Choose the LLM based on the model name
    if model_name == "gpt-3.5-turbo":
        llm = ChatOpenAI(model="gpt-3.5-turbo",
                         temperature=0.7,
                         api_key=os.getenv('OAI_API_KEY'))
    elif model_name == "gpt-4o":
        llm = ChatOpenAI(model="gpt-4o",
                         temperature=0.7,
                         api_key=os.getenv('OAI_API_KEY'))
    elif model_name == "claude-sonnet":
        llm = ChatAnthropic(model="claude-3-sonnet-20240229",
                            temperature=0.7,
                            api_key=os.getenv('CLAUDE_API_KEY'))
    elif model_name == "claude-opus":
        llm = ChatAnthropic(model="claude-3-opus-20240229",
                            temperature=0.7,
                            api_key=os.getenv('CLAUDE_API_KEY'))
    elif model_name == "google-gemini":
        llm = ChatGoogleGenerativeAI(
            model="gemini-pro",
            temperature=0.7,
            google_api_key=os.getenv('GEMINI_API_KEY'))
    elif model_name == "llama3-groq":
        llm = ChatGroq(model="llama3-70b-8192",
                       temperature=0.7,
                       groq_api_key=os.getenv('GROQ_API_KEY'))
    else:
        raise ValueError(f"Unsupported model name: {model_name}")

    # 2. Define the prompt template
    prompt = ChatPromptTemplate.from_template(
        "You are a helpful assistant whose main aim is to assist the user in answering their questions to the BEST of your ABILITY AND KNOWLEDGE. If you don't know, just say you don't know. Think step by step before answering any question. {question}"
    )

    # 3. Create a memory for conversation history
    memory = ConversationBufferMemory(memory_key="chat_history")

    # 4. Construct the chain
    chain = {
        'question': RunnablePassthrough()
    } | prompt | llm | StrOutputParser()

    # 5. Run the chain and return the output
    output = chain.invoke({"question": query})
    return output
