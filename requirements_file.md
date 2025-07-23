# Core Dependencies
requests>=2.28.0
urllib3>=1.26.0

# Optional Dependencies for Enhanced Functionality
colorama>=0.4.6          # Cross-platform colored terminal output
python-dotenv>=1.0.0     # Environment variable management
dnspython>=2.3.0         # Advanced DNS operations
cryptography>=40.0.0     # SSL/TLS analysis
python-nmap>=0.7.1       # Advanced port scanning (requires nmap binary)

# Database Support (Optional)
sqlalchemy>=2.0.0        # Database ORM
sqlite3                  # Built into Python standard library

# Report Generation (Optional)  
jinja2>=3.1.0           # HTML report templating
matplotlib>=3.7.0       # Chart generation for reports
plotly>=5.14.0          # Interactive charts

# Development Dependencies (Optional)
pytest>=7.3.0           # Testing framework
pytest-cov>=4.1.0      # Coverage reporting
black>=23.3.0           # Code formatting
flake8>=6.0.0           # Linting
mypy>=1.3.0             # Type checking

# Web Scraping Enhancement (Optional)
beautifulsoup4>=4.12.0  # HTML parsing
lxml>=4.9.0             # XML/HTML parser
selenium>=4.9.0         # Browser automation (if needed)

# Network Tools (Optional)
scapy>=2.5.0            # Advanced network packet manipulation
netaddr>=0.8.0          # IP address manipulation
ipwhois>=1.2.0          # WHOIS information retrieval

# API Client Libraries (Optional)
shodan>=1.28.0          # Shodan API client
virustotal-api>=1.1.11  # VirusTotal API client

# Performance and Monitoring (Optional)
psutil>=5.9.0           # System and process monitoring
memory-profiler>=0.60.0 # Memory usage profiling

# Async Support (Optional - for future async implementation)
aiohttp>=3.8.0          # Async HTTP client
asyncio>=3.4.3          # Async I/O support
aiofiles>=23.1.0        # Async file operations

# Configuration Management (Optional)
pydantic>=1.10.0        # Data validation and settings management
click>=8.1.0            # Command line interface enhancement
rich>=13.3.0            # Rich text and beautiful formatting

# Security Libraries (Optional)
certifi>=2023.5.7       # Certificate validation
pyopenssl>=23.1.1       # OpenSSL bindings
