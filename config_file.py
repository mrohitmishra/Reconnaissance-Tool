#!/usr/bin/env python3
"""
Configuration file for Bug Bounty Reconnaissance Tool
Contains API keys, settings, and customizable parameters
"""

import os
from typing import List, Dict, Any

class Config:
    """Configuration class for the reconnaissance tool"""
    
    # API Keys (set these as environment variables for security)
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', None)
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', None)
    SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY', None)
    CENSYS_API_ID = os.getenv('CENSYS_API_ID', None)
    CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', None)
    
    # Threading Configuration
    DEFAULT_THREADS = 50
    PORT_SCAN_THREADS = 100
    DIRECTORY_SCAN_THREADS = 20
    SUBDOMAIN_THREADS = 75
    
    # Timeout Settings (in seconds)
    REQUEST_TIMEOUT = 10
    DNS_TIMEOUT = 5
    SSL_TIMEOUT = 10
    SOCKET_TIMEOUT = 3
    
    # Rate Limiting
    REQUESTS_PER_SECOND = 10
    DELAY_BETWEEN_REQUESTS = 0.1
    API_DELAY = 1.0  # Delay between API calls
    
    # User Agents for Rotation
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]
    
    # Common Ports for Scanning
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 9300, 27017
    ]
    
    # Extended Port List (for comprehensive scans)
    EXTENDED_PORTS = [
        21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 5984, 6379,
        8000, 8080, 8443, 8888, 9200, 9300, 9999, 27017, 27018, 27019,
        50000, 50070, 50030
    ]
    
    # Directory Discovery Wordlists
    COMMON_DIRECTORIES = [
        'admin', 'administrator', 'login', 'dashboard', 'panel', 'api',
        'v1', 'v2', 'v3', 'test', 'dev', 'development', 'staging',
        'backup', 'backups', 'old', 'new', 'tmp', 'temp', 'config',
        'conf', 'configuration', 'upload', 'uploads', 'files', 'file',
        'download', 'downloads', 'docs', 'doc', 'documentation',
        'support', 'help', 'about', 'contact', 'search', 'beta',
        'demo', 'example', 'sample', 'static', 'assets', 'resources'
    ]
    
    # CMS-specific paths
    CMS_PATHS = {
        'wordpress': [
            'wp-admin', 'wp-content', 'wp-includes', 'wp-config.php',
            'wp-config.php.bak', 'wp-config.txt', 'xmlrpc.php'
        ],
        'drupal': [
            'admin', 'user', 'node', 'sites/default/files',
            'sites/default/settings.php', 'CHANGELOG.txt'
        ],
        'joomla': [
            'administrator', 'components', 'modules', 'plugins',
            'templates', 'configuration.php', 'htaccess.txt'
        ]
    }
    
    # File Extensions to Look For
    INTERESTING_EXTENSIONS = [
        '.env', '.git', '.svn', '.DS_Store', '.htaccess', '.htpasswd',
        '.backup', '.bak', '.old', '.orig', '.tmp', '.config',
        '.conf', '.log', '.sql', '.db', '.sqlite', '.json', '.xml'
    ]
    
    # Technology Detection Patterns
    TECHNOLOGY_PATTERNS = {
        'WordPress': [
            r'wp-content', r'wp-includes', r'WordPress', r'wp-json',
            r'/wp-admin/', r'wp_enqueue_script'
        ],
        'Drupal': [
            r'Drupal', r'sites/default/files', r'/user/login',
            r'drupal.js', r'Drupal.settings'
        ],
        'Joomla': [
            r'Joomla', r'components/com_', r'/administrator/',
            r'joomla.js', r'option=com_'
        ],
        'Laravel': [
            r'laravel_session', r'Laravel', r'_token',
            r'laravel.js', r'csrf-token'
        ],
        'Django': [
            r'django', r'csrfmiddlewaretoken', r'Django',
            r'__admin_media_prefix__', r'django.jQuery'
        ],
        'React': [
            r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
            r'React.createElement', r'react-dom'
        ],
        'Angular': [
            r'angular', r'ng-version', r'Angular',
            r'ng-app', r'angular.js'
        ],
        'Vue.js': [
            r'vue', r'Vue.js', r'v-if', r'v-for', r'vue.js'
        ],
        'jQuery': [
            r'jquery', r'jQuery', r'\$\(document\)\.ready'
        ],
        'Bootstrap': [
            r'bootstrap', r'Bootstrap', r'bootstrap.min.css'
        ]
    }
    
    # Security Headers to Check
    SECURITY_HEADERS = [
        'X-Frame-Options',
        'X-XSS-Protection', 
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Powered-By',
        'Server',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials',
        'X-Robots-Tag'
    ]
    
    # Common Subdomains for DNS Enumeration
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'development',
        'staging', 'api', 'app', 'mobile', 'secure', 'vpn', 'ssh',
        'remote', 'blog', 'shop', 'store', 'support', 'help', 'docs',
        'documentation', 'wiki', 'forum', 'chat', 'cdn', 'static',
        'media', 'images', 'img', 'assets', 'files', 'download',
        'uploads', 'beta', 'demo', 'sandbox', 'portal', 'dashboard',
        'panel', 'cpanel', 'whm', 'webmail', 'email', 'smtp', 'pop',
        'imap', 'ns', 'ns1', 'ns2', 'dns', 'mx', 'backup', 'db',
        'database', 'sql', 'mysql', 'postgres', 'redis', 'monitoring',
        'stats', 'analytics', 'status', 'health'
    ]
    
    # Output Configuration
    OUTPUT_FORMATS = ['json', 'xml', 'html', 'csv', 'txt']
    DEFAULT_OUTPUT_FORMAT = 'json'
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'recon_tool.log'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Database Configuration (for result storage)
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///recon_results.db')
    
    # Proxy Configuration
    HTTP_PROXY = os.getenv('HTTP_PROXY', None)
    HTTPS_PROXY = os.getenv('HTTPS_PROXY', None)
    
    # SSL Configuration
    VERIFY_SSL = True
    SSL_CERT_PATH = None
    
    @classmethod
    def load_from_file(cls, config_file: str) -> Dict[str, Any]:
        """Load configuration from external file"""
        try:
            import json
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config file: {e}")
            return {}
    
    @classmethod
    def get_api_keys(cls) -> Dict[str, str]:
        """Get all available API keys"""
        return {
            'shodan': cls.SHODAN_API_KEY,
            'virustotal': cls.VIRUSTOTAL_API_KEY,
            'securitytrails': cls.SECURITYTRAILS_API_KEY,
            'censys_id': cls.CENSYS_API_ID,
            'censys_secret': cls.CENSYS_API_SECRET
        }
    
    @classmethod
    def validate_config(cls) -> bool:
        """Validate configuration settings"""
        issues = []
        
        # Check threading limits
        if cls.DEFAULT_THREADS > 200:
            issues.append("DEFAULT_THREADS too high, may cause resource issues")
        
        # Check timeout values
        if cls.REQUEST_TIMEOUT < 1:
            issues.append("REQUEST_TIMEOUT too low")
        
        # Check rate limiting
        if cls.REQUESTS_PER_SECOND > 100:
            issues.append("REQUESTS_PER_SECOND may be too aggressive")
        
        if issues:
            print("Configuration warnings:")
            for issue in issues:
                print(f"  - {issue}")
            return False
        
        return True

# Environment-specific configurations
class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEFAULT_THREADS = 10
    REQUEST_TIMEOUT = 5
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """Production environment configuration"""
    DEFAULT_THREADS = 50
    REQUEST_TIMEOUT = 10
    LOG_LEVEL = 'INFO'
    VERIFY_SSL = True

class TestingConfig(Config):
    """Testing environment configuration"""
    DEFAULT_THREADS = 5
    REQUEST_TIMEOUT = 3
    LOG_LEVEL = 'DEBUG'
    VERIFY_SSL = False

# Configuration factory
def get_config(env: str = None) -> Config:
    """Get configuration based on environment"""
    env = env or os.getenv('RECON_ENV', 'production').lower()
    
    configs = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    return configs.get(env, ProductionConfig)()
