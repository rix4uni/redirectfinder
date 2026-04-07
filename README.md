## RedirectFinder

A fast and efficient Open Redirect vulnerability scanner written in Go. This tool automates the process of testing URLs for open redirect vulnerabilities by replacing parameter values with redirect payloads and checking HTTP responses.

## Features

- 🔍 **Automatic Open Redirect Testing**: Tests URLs with multiple payloads to detect open redirect vulnerabilities
- 🚀 **Concurrent Scanning**: Process multiple URLs in parallel for faster results
- 🎨 **Colored Output**: Color-coded results (Red for VULNERABLE, Green for NOT VULNERABLE)
- 📦 **Auto-Download Payloads**: Automatically downloads default redirect payloads on first run
- 🔄 **URL Filtering**: Automatically filters URLs using `urldedupe`, `grep`, and `egrep`
- 🧭 **Domain Payload Mode**: Extract unique domains and append payloads to the end of the domain using `sort -u`
- 🌐 **URL-Encoded Support**: Handles both `=` and `%3D` (URL-encoded equals) in parameters
- ⚡ **Configurable**: Customizable timeout, concurrency, and output options
- 📝 **Flexible Payloads**: Use single payload, comma-separated payloads, or payload file

## Installation

### Prerequisites
```
git clone https://github.com/ameenmaali/urldedupe.git --depth 1 &>/dev/null && cd urldedupe && cmake CMakeLists.txt &>/dev/null && make &>/dev/null && mv urldedupe /usr/local/bin/ && cd .. && rm -rf urldedupe
```

## Installation
### Install via Go
```
go install github.com/rix4uni/redirectfinder@latest
```

### Download Prebuilt Binaries
```
wget https://github.com/rix4uni/redirectfinder/releases/download/v0.0.3/redirectfinder-linux-amd64-0.0.3.tgz
tar -xvzf redirectfinder-linux-amd64-0.0.3.tgz
rm -rf redirectfinder-linux-amd64-0.0.3.tgz
mv redirectfinder ~/go/bin/redirectfinder
```

Or download the [latest release](https://github.com/rix4uni/redirectfinder/releases) for your platform.

### Compile from Source
```
git clone --depth 1 https://github.com/rix4uni/redirectfinder.git
cd redirectfinder; go install
```

## Usage

### Basic Usage

```yaml
# Test a single URL
echo "https://example.com/page?redirect=test" | redirectfinder

# Test multiple URLs from a file
cat urls.txt | redirectfinder

# With custom single payload
cat urls.txt | redirectfinder -p "https://bing.com"

# With comma-separated payloads
cat urls.txt | redirectfinder -p "https://bing.com, //bing.com"

# With custom payloads file
cat urls.txt | redirectfinder -p payloads.txt

# Extract unique domains and append payloads to the domain
cat urls.txt | redirectfinder --domain

# Domain-only payload scanning (no parameter rewriting)
cat urls.txt | redirectfinder --only-domain

# Domain-only payload scanning with a single domain
echo "https://admin.dell.com" | redirectfinder --only-domain
```

### Command-Line Flags

| Flag | Short | Description | Default |
|------|------|-------------|---------|
| `--payload` | `-p` | Payload(s) to use: single (`"https://bing.com"`), comma-separated (`"https://bing.com, //bing.com"`), or file path (`payloads.txt`) | `~/.config/redirectfinder/payloads.txt` |
| `--redirect` | | Domain to check for in Location header | `bing.com` |
| `--timeout` | | HTTP request timeout in seconds | `30` |
| `--concurrent` | | Number of concurrent URL scans | `50` |
| `--vuln` | | Show only VULNERABLE URLs | `false` |
| `--silent` | | Silent mode (suppress banner) | `false` |
| `--version` | | Print version and exit | `false` |
| `--nc` | | Disable colored output | `false` |
| `--verbose` | | Show verbose output (download messages, etc.) | `false` |
| `--domain` | | Extract unique domains and append payloads to the end of the domain | `false` |
| `--only-domain` | | Extract unique domains and append payloads to the end of the domain (domain mode only) | `false` |

### Examples

#### Test with default settings
```yaml
cat urls.txt | redirectfinder
```

#### Test with custom timeout and concurrency
```yaml
cat urls.txt | redirectfinder --timeout 60 --concurrent 100
```

#### Show only vulnerable URLs
```yaml
cat urls.txt | redirectfinder --vuln
```

#### Silent mode with no colors
```yaml
cat urls.txt | redirectfinder --silent --nc
```

#### Custom single payload
```yaml
cat urls.txt | redirectfinder -p "https://bing.com"
```

#### Multiple comma-separated payloads
```yaml
cat urls.txt | redirectfinder -p "https://bing.com, //bing.com"
```

#### Custom payloads file
```yaml
cat urls.txt | redirectfinder -p /path/to/custom-payloads.txt
```

#### Verbose mode (shows download messages)
```yaml
cat urls.txt | redirectfinder --verbose
```

#### Domain payload mode (unique domains)
```yaml
cat urls.txt | redirectfinder --domain
```

#### Domain-only payload mode
```yaml
cat urls.txt | redirectfinder --only-domain
```

#### Custom redirect domain
```yaml
cat urls.txt | redirectfinder --redirect google.com
```

## How It Works

1. **URL Input**: Reads URLs from stdin (supports both `echo` and `cat`)

2. **URL Filtering**: Automatically filters URLs using:
   ```yaml
   urldedupe -s | grep -aE '=|%3D' | egrep -aiv '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)'
   ```
   - Deduplicates URLs
   - Filters URLs containing `=` or `%3D` (URL-encoded equals)
   - Excludes URLs with static file extensions

3. **Payload Testing**: For each URL:
   - Replaces all parameter values with each redirect payload
   - Handles both `=` and `%3D` separators
   - Makes HTTP GET requests with modified URLs (without following redirects)
   - Checks HTTP response for redirect status code (3xx) and Location header

4. **Vulnerability Detection**: The tool detects open redirect vulnerabilities by checking:
   - HTTP Status Code is `3xx` (any redirect: 300, 301, 302, 303, 304, 307, 308)
   - `Location` header contains the specified domain (default: `bing.com`, customizable with `--redirect` flag, case-insensitive)
   - Both conditions must be true for vulnerability detection

5. **Output**: Displays results:
   - **VULNERABLE**: Red colored output when open redirect vulnerability is detected
   - **NOT VULNERABLE**: Green colored output when no vulnerability is found

## Default Payloads

On first run, if no `-p` flag is provided, the tool automatically:
- Creates `~/.config/redirectfinder/` directory
- Downloads default redirect payloads from: `https://raw.githubusercontent.com/rix4uni/WordList/refs/heads/main/payloads/redirect/redirect-medium.txt`
- Saves them as `~/.config/redirectfinder/payloads.txt`

You can override the default payloads using the `--payload` flag with:
- Single payload: `-p "https://bing.com"`
- Multiple payloads: `-p "https://bing.com, //bing.com"`
- Payload file: `-p payloads.txt`

Use `--verbose` flag to see download messages.

## Output Format

### Colored Output (Default)
```yaml
VULNERABLE: https://example.com/page?redirect=https://bing.com
NOT VULNERABLE: https://example.com/page?redirect=test
```

### No Color Output (`--nc` flag)
```yaml
VULNERABLE: https://example.com/page?redirect=https://bing.com
NOT VULNERABLE: https://example.com/page?redirect=test
```

## URL Parameter Handling

The tool supports both standard and URL-encoded parameter separators:
- Standard: `?redirect=value`
- URL-encoded: `?redirect%3Dvalue`

Both formats are automatically detected and tested.

## Domain Payload Mode

There are two domain payload modes:

- `--domain`: runs parameter rewriting first, then runs domain payload scanning.
- `--only-domain`: runs only the domain payload scanning (no parameter rewriting). If both flags are set, `--only-domain` takes precedence.

Domain payload scanning works as follows:

1. **Domain Extraction**: Reads URLs from stdin, extracts only http/https domains, and deduplicates them using:
   ```yaml
   sort -u
   ```
2. **Payload Testing**: For each unique domain, appends each payload directly to the end of the domain and sends the request.
3. **Vulnerability Detection**: Uses the same redirect rules and `--redirect` domain matching as the parameter mode.

## Vulnerability Detection

The tool detects open redirect vulnerabilities by checking HTTP responses for:
1. **Status Code**: Must be `3xx` (300-399) - any redirect status code
2. **Location Header**: Must contain the specified domain (default: `bing.com`, customizable with `--redirect` flag, case-insensitive)

Both conditions must be true to confirm an open redirect vulnerability. The HTTP client is configured to not follow redirects automatically, allowing the tool to inspect the redirect response directly.

You can specify a custom domain to check for using the `--redirect` flag:
```yaml
cat urls.txt | redirectfinder --redirect google.com
```

## Performance

- **Concurrent Processing**: By default, processes 50 URLs concurrently
- **Configurable Concurrency**: Adjust with `--concurrent` flag
- **Timeout Control**: Configurable HTTP timeout with `--timeout` flag

