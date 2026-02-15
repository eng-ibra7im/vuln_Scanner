# System Architecture

## Overview

The Subdomain Enumeration Orchestrator is designed as a modular, scalable system for coordinating multiple subdomain discovery tools and producing structured output for dashboard integration.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                     User Interface                       │
├─────────────────────────────────────────────────────────┤
│  CLI (cli.py)  │  API Server (api.py)  │  Direct Import │
└────────┬─────────────────┬─────────────────────┬────────┘
         │                 │                     │
         └─────────────────┼─────────────────────┘
                          │
         ┌────────────────┴────────────────┐
         │   Orchestrator (orchestrator.py)  │
         │  - Execution Plan Generation     │
         │  - Tool Coordination             │
         │  - Result Aggregation            │
         └────────┬────────────────┬────────┘
                  │                │
        ┌─────────┴────────┐  ┌───┴──────────────┐
        │  Analyzer        │  │  External Tools   │
        │  (analyzer.py)   │  │  - subfinder      │
        │  - Validation    │  │  - amass          │
        │  - Classification│  │  - assetfinder    │
        │  - Prioritization│  │  - sublist3r      │
        └─────────┬────────┘  │  - ffuf           │
                  │           └──────────────────┘
        ┌─────────┴────────┐
        │  Formatter       │
        │  (formatter.py)  │
        │  - JSON Output   │
        │  - CSV Export    │
        │  - Markdown      │
        └─────────┬────────┘
                  │
        ┌─────────┴────────┐
        │   Configuration  │
        │   (config.py)    │
        └──────────────────┘
```

## Component Details

### 1. Orchestrator (`orchestrator.py`)

**Responsibilities:**
- Generate execution plans for each tool
- Coordinate tool execution (parallel or sequential)
- Aggregate raw results from all tools
- Handle errors and timeouts
- Coordinate with analyzer and formatter

**Key Classes:**
- `SubdomainOrchestrator` - Main orchestration class
- `ExecutionPlan` - Represents a tool execution plan
- `ToolResult` - Stores results from individual tools

**Key Methods:**
- `generate_execution_plan()` - Creates tool-specific command plans
- `execute_tool()` - Executes a single tool
- `execute_all()` - Coordinates multiple tool executions
- `orchestrate()` - Main entry point for full workflow

### 2. Analyzer (`analyzer.py`)

**Responsibilities:**
- Deduplicate discovered subdomains
- Validate subdomains via DNS resolution
- Classify subdomains by pattern matching
- Assign priority scores
- Detect naming patterns and trends
- Generate statistics

**Key Classes:**
- `SubdomainAnalyzer` - Main analysis engine

**Classification Categories:**
- Development (dev, test, staging, qa)
- Admin (admin, panel, dashboard)
- API (api, rest, graphql)
- Mail (mail, smtp, webmail)
- VPN (vpn, remote, citrix)
- Storage (s3, cdn, static)
- Database (db, mysql, postgres)
- CI/CD (jenkins, gitlab)
- Monitoring (grafana, prometheus)
- Auth (sso, login, oauth)

**Priority Scoring Algorithm:**
```
Base Score = 0

+ 10 if DNS validated
+ 5 per classification
+ 10 for high-value classifications (admin, api, database, vpn, dev)
+ 8 if MX records exist
+ 5 if depth = 1 (shallow subdomain)
- 5 if depth > 3 (deep subdomain)
- 20 if wildcard detected

Final Priority:
- High: Score >= 20
- Medium: Score >= 10
- Low: Score < 10
```

### 3. Formatter (`formatter.py`)

**Responsibilities:**
- Format analyzed results into structured JSON
- Generate CSV exports
- Generate Markdown reports
- Create actionable recommendations
- Ensure consistent output format

**Key Classes:**
- `ResultFormatter` - Formatting engine

**Output Sections:**
1. **Metadata** - Scan information, timestamps
2. **Summary** - High-level statistics
3. **Subdomains** - Detailed subdomain list with classifications
4. **Statistics** - Tool performance, distributions
5. **Patterns** - Detected naming patterns
6. **Tool Performance** - Individual tool metrics
7. **Tool Coverage** - Contribution analysis
8. **Recommendations** - Security recommendations

### 4. Configuration (`config.py`)

**Responsibilities:**
- Load and save configuration
- Provide default configuration
- Tool enable/disable management
- Setting management

**Key Classes:**
- `Config` - Configuration container

**Configuration Categories:**
- Tool configurations
- Execution settings
- Output settings
- Analysis settings
- Filtering options

### 5. CLI Interface (`cli.py`)

**Responsibilities:**
- Provide user-friendly command-line interface
- Parse command-line arguments
- Override configuration options
- Display progress and results

**Features:**
- Multiple output formats (JSON, CSV, Markdown)
- Tool selection
- Filtering options
- Verbose mode
- Summary-only mode

### 6. API Server (`api.py`)

**Responsibilities:**
- Provide REST API for external integration
- Manage scan jobs asynchronously
- Track job status
- Serve results via HTTP

**Endpoints:**
- `GET /api/health` - Health check
- `GET /api/tools` - List available tools
- `GET /api/config` - Get configuration
- `POST /api/scan` - Start new scan
- `GET /api/scan/:id` - Get scan status
- `GET /api/scan/:id/results` - Get scan results
- `GET /api/jobs` - List all jobs
- `GET /api/stats` - System statistics

## Data Flow

### Typical Scan Flow:

1. **Input**: Target domain (e.g., "example.com")

2. **Plan Generation**:
   - Orchestrator generates ExecutionPlan for each enabled tool
   - Plans include: command, timeout, priority, description

3. **Tool Execution**:
   - Tools executed in parallel or sequential based on config
   - Each tool produces raw subdomain list
   - Errors and timeouts handled gracefully

4. **Raw Aggregation**:
   - All subdomains collected into single list
   - Tool metadata preserved (which tool found what)

5. **Analysis**:
   - Deduplication (case-insensitive)
   - Cleaning (remove invalid entries)
   - DNS validation (A records, CNAME, MX)
   - Classification (pattern matching)
   - Priority assignment (scoring algorithm)
   - Pattern detection (series, prefixes)

6. **Formatting**:
   - Structured JSON generation
   - Summary statistics calculation
   - Recommendations generation
   - Export format conversion (CSV, Markdown)

7. **Output**:
   - JSON to stdout or file
   - Optional save to results/ directory
   - API response (if using API mode)

## Scalability Considerations

### Parallel Execution
- Tools run concurrently using asyncio
- Configurable worker limit prevents resource exhaustion
- Each tool has independent timeout

### Large Result Sets
- Streaming results (can be implemented)
- Pagination for API responses
- Efficient deduplication using sets
- Lazy DNS validation (can be toggled)

### Performance Optimization
- DNS resolver with connection pooling
- Batch DNS queries
- Configurable timeouts
- Skip expensive operations (HTTP checks) by default

## Error Handling

### Tool Execution Errors
- Timeout handling with configurable limits
- Missing tool detection
- Command execution errors
- Output parsing failures

### Network Errors
- DNS resolution failures
- Connection timeouts
- Rate limiting handling

### Recovery Strategies
- Continue on tool failure (don't abort entire scan)
- Graceful degradation (partial results)
- Detailed error reporting
- Retry logic (can be implemented)

## Security Considerations

### Input Validation
- Domain format validation
- Command injection prevention
- Path traversal prevention

### Output Sanitization
- No credentials in output
- Sanitized error messages
- Configurable verbosity

### Resource Limits
- Timeout enforcement
- Memory usage monitoring
- Concurrent execution limits

## Extensibility

### Adding New Tools

To add a new subdomain enumeration tool:

1. Add tool configuration to `Config` class
2. Add execution plan in `generate_execution_plan()`
3. Implement tool-specific output parsing in `_parse_tool_output()`
4. Update documentation

Example:
```python
# In orchestrator.py
if self.config.tools.get('newtool', {}).get('enabled', False):
    plans.append(ExecutionPlan(
        tool='newtool',
        command=['newtool', '-d', target_domain],
        timeout=300,
        priority=2,
        description='New tool description'
    ))
```

### Adding New Classifications

To add new subdomain classifications:

1. Add pattern to `interesting_patterns` in `analyzer.py`
2. Update recommendations logic in `formatter.py`

Example:
```python
# In analyzer.py
self.interesting_patterns = {
    'newcategory': r'(pattern1|pattern2|pattern3)',
    # ... existing patterns
}
```

### Custom Output Formats

To add new output formats:

1. Add method to `ResultFormatter` class
2. Update CLI to support new format
3. Add format examples to documentation

## Testing Strategy

### Unit Tests
- Test each component independently
- Mock external tool execution
- Test classification logic
- Test priority scoring

### Integration Tests
- Test full workflow
- Test with sample tool outputs
- Test error scenarios
- Test configuration loading

### Manual Testing
- Test with real tools on test domains
- Verify DNS validation
- Check output formats
- Validate API endpoints

## Deployment Options

### Standalone CLI
- Direct execution on command line
- Cron job scheduling
- Shell script integration

### API Server
- Flask development server (testing)
- Production WSGI server (gunicorn, uwsgi)
- Docker container deployment
- Kubernetes pod deployment

### Library Import
- Import as Python module
- Programmatic control
- Custom integration

## Future Enhancements

### Potential Features
1. Database storage for historical results
2. Comparison with previous scans
3. Certificate Transparency log checking
4. HTTP/HTTPS probing
5. Screenshot capture
6. Vulnerability scanning integration
7. Real-time progress updates
8. WebSocket support for live updates
9. Machine learning for priority prediction
10. Distributed execution across multiple nodes

### Performance Improvements
1. Caching DNS results
2. Incremental scanning
3. Result streaming
4. Optimized DNS resolution
5. Connection pooling

### Security Features
1. Authentication and authorization
2. API rate limiting
3. Input sanitization
4. Audit logging
5. Encrypted storage
