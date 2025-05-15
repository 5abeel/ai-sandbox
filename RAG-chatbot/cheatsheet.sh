# Enable internet connectivity

# On host
ssh -fgCNL 10.10.0.3:911:proxy-dmz.intel.com:911 localhost

# On ACC
export https_proxy=http://10.10.0.3:911
export http_proxy=http://10.10.0.3:911


# Step 1 - trying BitNet
# ######################

# Clone the repository
git clone --recursive https://github.com/microsoft/BitNet.git
cd BitNet

# Install dependencies
dnf install cmake clang clang-tools-extra llvm-devel
pip install -r requirements.txt

# Install Clang 18 or higher using LLVM's installation script
bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"

## above didnt work because of lsb_release issue, so manually way
wget https://apt.llvm.org/llvm.sh
vi llvm.sh
# replace with os-release lines instead
# DISTRO=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
# VERSION_CODENAME=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release | tr -d '"')
# VERSION=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release | tr -d '"')

chmod +x llvm.sh
./llvm.sh


# Install huggingface-cli if not already installed
pip3 install huggingface_hub

# Download the official BitNet model
huggingface-cli download microsoft/BitNet-b1.58-2B-4T-gguf --local-dir models/BitNet-b1.58-2B-4T


# Set up the environment with the downloaded model
python setup_env.py -md models/BitNet-b1.58-2B-4T -q i2_s


# Running the inference
python3 run_inference.py -m models/BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf -p "You are a helpful assistant" -cnv


## >>> checkpoint. Works!

# Step 2: Building chatbot
# ########################


# 2.1 Need to export to ONNX for optimal performance on Intel IPUs
#### >>>> This seems to fail and a widely reported error. Recommendation is to use native BitNet tools rather
#### than trying to convert to PyTorch/ONNX. The BitNet repo is designed to work with GGUF format directly.
# First convert GGUF to PyTorch
pip install optimum[exporters]

# Create a simple script to load and convert the model
cat > convert_bitnet.py << 'EOF'
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# Load model from GGUF (this is a simplification - you may need a custom loader)
model_path = "models/BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf"
model = AutoModelForCausalLM.from_pretrained("microsoft/BitNet-b1.58-2B-4T")
tokenizer = AutoTokenizer.from_pretrained("microsoft/BitNet-b1.58-2B-4T")

# Save as PyTorch model
model.save_pretrained("bitnet_pytorch")
tokenizer.save_pretrained("bitnet_pytorch")
EOF

python convert_bitnet.py

# Now export to ONNX using Optimum
optimum-cli export onnx --model bitnet_pytorch bitnet_onnx/

# ############ above 2.1 fails ####################


# 2.2 install RAG components
pip install langchain chromadb sentence-transformers flask pypdf tf-keras
pip install -U langchain-community
pip install -U langchain-huggingface
pip install "unstructured[all-docs]"
pip install -U langchain-chroma

# 2.3 download IPU docs repo to /root/ipu-docs

# 2.3.5 sqlite error seen in next step, so need to upgrade

sudo dnf groupinstall "Development Tools"
sudo dnf install wget tar
wget https://www.sqlite.org/2021/sqlite-autoconf-3350400.tar.gz
tar -xvzf sqlite-autoconf-3350400.tar.gz
cd sqlite-autoconf-3350400
./configure --prefix=$HOME/opt/sqlite
make
make install
echo 'export PATH=$HOME/opt/sqlite/bin:$PATH' >> ~/.bash_profile
echo 'export LD_LIBRARY_PATH=$HOME/opt/sqlite/lib' >> ~/.bash_profile
echo 'export LD_RUN_PATH=$HOME/opt/sqlite/lib' >> ~/.bash_profile
source ~/.bash_profile
sqlite3 --version


# 2.4 create document processing script

cat > process_documents.py << 'EOF'
import os
from langchain.document_loaders import DirectoryLoader, PyPDFLoader, TextLoader, UnstructuredMarkdownLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma

# Configure embedding model
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

# Configure document loading with additional file types
loader_mapping = {
    ".pdf": (PyPDFLoader, {}),
    ".txt": (TextLoader, {"encoding": "utf8"}),
    ".md": (UnstructuredMarkdownLoader, {}),
    ".rst": (TextLoader, {"encoding": "utf8"}),
}

# Path to your IPU documentation
doc_path = "/root/ipu-docs"

# Load documents using the mapping
loader = DirectoryLoader(doc_path, loader_mapping=loader_mapping, recursive=True)
documents = loader.load()

# Special handling for README files without extensions
readme_files = []
for root, _, files in os.walk(doc_path):
    for file in files:
        if file.upper() == "README" or file.startswith("README."):
            file_path = os.path.join(root, file)
            try:
                loader = TextLoader(file_path, encoding="utf8")
                readme_docs = loader.load()
                readme_files.extend(readme_docs)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

# Combine all documents
documents.extend(readme_files)
print(f"Loaded {len(documents)} documents")

# Split documents into chunks
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
chunks = text_splitter.split_documents(documents)
print(f"Split into {len(chunks)} chunks")

# Create vector store
db = Chroma.from_documents(chunks, embeddings, persist_directory="./chroma_db")
db.persist()
print("Vector database created and persisted")
EOF

# Run the document processing
python process_documents.py

### >>> checkpoint. Vector database created!

# 3. Text-based BitNet chatbot

cat > ipu_chatbot_bitnet.py << 'EOF'
import os
import subprocess
import tempfile
import signal
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
import time
import sys

# Set environment variables for better performance and to avoid warnings
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "16"  # Adjust based on your CPU
os.environ["KMP_AFFINITY"] = "granularity=fine,compact,1,0"

# Set up colored output for better terminal experience
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Load the vector database
print(f"{Colors.HEADER}Loading embeddings model and vector database...{Colors.ENDC}")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
db = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)
print(f"{Colors.GREEN}Database loaded successfully!{Colors.ENDC}")

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def process_query(question):
    print(f"{Colors.BLUE}Searching for relevant documents...{Colors.ENDC}")

    # Retrieve relevant documents
    docs = db.similarity_search(question, k=5)

    # Debug: Print retrieved documents
    print(f"{Colors.BLUE}Retrieved {len(docs)} documents{Colors.ENDC}")
    for i, doc in enumerate(docs):
        print(f"{Colors.BLUE}Document {i+1}: {doc.page_content[:100]}...{Colors.ENDC}")

    context = "\n\n".join([doc.page_content for doc in docs])

    # Create prompt with retrieved context
    prompt = f"""### System:
You are IPU-Doctor, an expert on Infrastructure Processing Units.
### Knowledge:
{context}
### User:
{question}
### Assistant:"""

    # Debug: Print prompt being sent to BitNet
    print(f"{Colors.BLUE}Sending prompt to BitNet (length: {len(prompt)} chars){Colors.ENDC}")

    # Save prompt to temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(prompt)
        prompt_file = f.name

    print(f"{Colors.BLUE}Generating response with BitNet...{Colors.ENDC}")

    # Run BitNet inference with adjusted parameters
    cmd = [
        "python", "BitNet/run_inference.py",
        "-m", "BitNet/models/BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf",
        "-f", prompt_file,
        "-n", "512",  # Generate up to 512 tokens
        "--temp", "0.9",  # Add temperature parameter
        "--top_p", "0.9"  # Add top_p parameter
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    # Clean up temporary file
    os.unlink(prompt_file)

    # Extract answer from BitNet output
    response = result.stdout.strip()

    # Debug: Print raw response length
    print(f"{Colors.BLUE}Raw response length: {len(response)} chars{Colors.ENDC}")

    # Implement fallback response if the model returns empty output
    if not response.strip():
        response = "I don't have enough information to answer that question based on the available IPU documentation. Please try asking something else or rephrase your question."

    # Return the answer
    return response

def main():
    clear_screen()
    print(f"{Colors.HEADER}{Colors.BOLD}IPU Documentation Chatbot{Colors.ENDC}")
    print(f"{Colors.HEADER}Type 'exit' to quit the chatbot{Colors.ENDC}")
    print(f"{Colors.HEADER}Type 'clear' to clear the screen{Colors.ENDC}")
    print("-" * 50)

    quit_requested = False

    def signal_handler(sig, frame):
        nonlocal quit_requested
        quit_requested = True
        print(f"\n{Colors.WARNING}Interrupt received, finishing current operation...{Colors.ENDC}")

    # Set up signal handler for graceful interruption
    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        while not quit_requested:
            print()
            try:
                question = input(f"{Colors.BOLD}You: {Colors.ENDC}")

                if quit_requested or question.lower() == 'exit':
                    print(f"{Colors.GREEN}Thank you for using the IPU Documentation Chatbot. Goodbye!{Colors.ENDC}")
                    break

                if question.lower() == 'clear':
                    clear_screen()
                    continue

                if not question.strip():
                    continue

                response = process_query(question)
                print(f"\n{Colors.GREEN}{Colors.BOLD}Assistant: {Colors.ENDC}{response}")
            except Exception as e:
                if not quit_requested:
                    print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
    except KeyboardInterrupt:
        # This should be caught by our signal handler, but just in case
        if not quit_requested:
            print(f"\n{Colors.GREEN}Chatbot terminated. Thank you for using the IPU Documentation Chatbot!{Colors.ENDC}")
    finally:
        # Restore original signal handler
        signal.signal(signal.SIGINT, original_handler)

if __name__ == "__main__":
    main()

EOF

# Run the chatbot
python ipu_chatbot_bitnet.py

### >>> checkpoint.  chatbot works, but not as well as expected

# 4. Text-based Ollama chatbot
curl -fsSL https://ollama.com/install.sh | sh
systemctl start ollama

# proxy settings
sudo systemctl edit ollama.service
Add following:
    
    [Service]
    Environment="HTTPS_PROXY=http://10.10.0.3:911/"

sudo systemctl daemon-reload && sudo systemctl restart ollama

# Pull the Llama 3 8B model
ollama pull llama3

# Verify the model is installed
ollama list

# chatbot to use ollama

cat > ipu_chatbot_ollama.py << 'EOF'
import os
import requests
import json
import signal
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
import time
import sys

# Set environment variables to bypass proxy for localhost connections
os.environ["TOKENIZERS_PARALLELISM"] = "false"
# os.environ["no_proxy"] = "localhost,127.0.0.1"
# os.environ["NO_PROXY"] = "localhost,127.0.0.1"

# Set up colored output for better terminal experience
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Load the vector database
print(f"{Colors.HEADER}Loading embeddings model and vector database...{Colors.ENDC}")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
db = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)
print(f"{Colors.GREEN}Database loaded successfully!{Colors.ENDC}")

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def process_query(question):
    print(f"{Colors.BLUE}Searching for relevant documents...{Colors.ENDC}")

    # Retrieve relevant documents
    docs = db.similarity_search(question, k=5)

    # Debug: Print retrieved documents
    print(f"{Colors.BLUE}Retrieved {len(docs)} documents{Colors.ENDC}")
    for i, doc in enumerate(docs):
        print(f"{Colors.BLUE}Document {i+1}: {doc.page_content[:100]}...{Colors.ENDC}")

    context = "\n\n".join([doc.page_content for doc in docs])

    # Create prompt with retrieved context
    prompt = f"""You are IPU-Doctor, an expert on Infrastructure Processing Units.
Use the following information to answer the user's question.
If you don't know the answer based on the provided information, say so.

Context information:
{context}

User question: {question}

Answer:"""

    print(f"{Colors.BLUE}Sending prompt to Llama 3...{Colors.ENDC}")

    # Call Ollama API to generate response with proxy bypass
    try:
        # Set proxies to None to bypass any system proxy settings
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                "model": "llama3",
                "prompt": prompt,
                "stream": True,
                "temperature": 0.7,
                "max_tokens": 512
            },
            proxies={"http": None, "https": None}  # Explicitly bypass proxies
        )

        response.raise_for_status()
        result = response.json()
        answer = result['response']

        print(f"{Colors.BLUE}Response received (length: {len(answer)} chars){Colors.ENDC}")
        return answer
    except Exception as e:
        print(f"{Colors.FAIL}Error calling Ollama API: {str(e)}{Colors.ENDC}")
        # Fallback to displaying document content
        for doc in docs:
            if any(keyword in doc.page_content.lower() for keyword in question.lower().split()):
                return f"Based on the IPU documentation, here's what I found:\n\n{doc.page_content}"

        return "I encountered an error while generating a response and couldn't find relevant information in the documentation."

def main():
    # clear_screen()
    print(f"{Colors.HEADER}{Colors.BOLD}IPU Documentation Chatbot (Powered by Llama 3){Colors.ENDC}")
    print(f"{Colors.HEADER}Type 'exit' to quit the chatbot{Colors.ENDC}")
    print(f"{Colors.HEADER}Type 'clear' to clear the screen{Colors.ENDC}")
    print("-" * 50)

    quit_requested = False

    def signal_handler(sig, frame):
        nonlocal quit_requested
        quit_requested = True
        print(f"\n{Colors.WARNING}Interrupt received, finishing current operation...{Colors.ENDC}")

    # Set up signal handler for graceful interruption
    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        while not quit_requested:
            print()
            try:
                question = input(f"{Colors.BOLD}You: {Colors.ENDC}")

                if quit_requested or question.lower() == 'exit':
                    print(f"{Colors.GREEN}Thank you for using the IPU Documentation Chatbot. Goodbye!{Colors.ENDC}")
                    break

                if question.lower() == 'clear':
                    clear_screen()
                    continue

                if not question.strip():
                    continue

                response = process_query(question)
                print(f"\n{Colors.GREEN}{Colors.BOLD}Assistant: {Colors.ENDC}{response}")
            except Exception as e:
                if not quit_requested:
                    print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
    finally:
        # Restore original signal handler
        signal.signal(signal.SIGINT, original_handler)

if __name__ == "__main__":
    main()
EOF

# Run the chatbot
python ipu_chatbot_ollama.py

### checkpoint.  chatbot works, but with some errors. 
## Llama3 8B requires 5.6GB in RAM (and 16GB recommended). Only had 2GB RAM available.

# 5. Tinyllama

ollama ps
ollama kill <model_name>

# Pull the Llama 3 8B model
ollama pull tinyllama

# edit ipu_chatbot_ollama.py to use 'tinyllama' instead of 'llama3' in model name.

# Run the chatbot
python ipu_chatbot_ollama.py






## Appendix: Ollama commands


# list models
ollama ls

# see running models
ollama ps
ollama stop tinyllama

systemctl restart ollama
systemctl status ollama

