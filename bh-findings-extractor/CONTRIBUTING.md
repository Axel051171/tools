# Contributing to BH Findings Extractor

First off, thanks for taking the time to contribute! 🎉

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs what actually happened
- **Sample data** (sanitized) if possible
- **Python version** and OS

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Use case** - Why is this feature needed?
- **Proposed solution** - How should it work?
- **Alternatives** - Other approaches you've considered

### Pull Requests

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Write tests for new functionality
4. Ensure all tests pass (`python tests/test_golden.py`)
5. Commit your changes (`git commit -m 'Add AmazingFeature'`)
6. Push to the branch (`git push origin feature/AmazingFeature`)
7. Open a Pull Request

## Development Setup

```bash
git clone https://github.com/Axel051171/tools.git
cd tools/bh-findings-extractor
pip install networkx  # Optional, for attack paths
python tests/test_golden.py  # Run tests
```

## Code Style

- Follow PEP 8
- Use type hints where practical
- Add docstrings to functions and classes
- Keep functions focused and small

## Adding New Security Findings

1. Create a new task class in `bh_findings_extractor.py`:

```python
class MyNewFindingTask(AnalysisTask):
    name = "my_new_finding"
    output_filename = "my_new_finding.txt"
    description = "Description for output"
    priority = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    def run(self, store, graph=None):
        fc = FindingCollection()
        # Your analysis logic here
        return fc
```

2. Add to `ALL_TASKS` list
3. Add tests
4. Update README

## Questions?

Feel free to open an issue for any questions!
