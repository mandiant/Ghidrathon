# Contributing

## Linting

### Requirements

Tool | Source |
|---| ---|
| isort | https://pypi.org/project/isort |
| black | https://pypi.org/project/black |
| google-java-format | https://github.com/google/google-java-format/releases/download/v1.19.2/google-java-format-1.19.2-all-deps.jar |

Use the following commands to identify format errors:
```
$ isort --profile black --length-sort --line-width 120 -c /local/path/to/src
$ black -l 120 -c /local/path/to/src
$ find /local/path/to/src -name "*.java" -type f -print | xargs java -jar google-java-format-1.19.2-all-deps.jar --dry-run --set-exit-if-changed
```
