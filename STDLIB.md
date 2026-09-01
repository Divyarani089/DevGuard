\# Standard Library Substitutions



DevGuard follows a zero-dependency approach wherever practical. The following

standard-library alternatives can replace commonly used third-party packages.



| # | Third-Party Package | Standard Library Replacement | Purpose |

|---|---------------------|------------------------------|---------|

| 1 | requests | urllib.request | HTTP requests |

| 2 | click | argparse | Command-line argument parsing |

| 3 | python-dotenv | os | Environment variable access |

| 4 | pathlib2 | pathlib | File and path handling |

| 5 | shutilwhich | shutil.which | Executable lookup |

| 6 | glob2 | glob | File pattern matching |

| 7 | colorama | ANSI escape sequences | Terminal text formatting |

| 8 | tomli | tomllib | TOML file parsing |

| 9 | simplejson | json | JSON encoding and decoding |

| 10 | configparser package alternatives | configparser | Configuration file parsing |



\## Rationale



Using Python's standard library where practical reduces external dependencies,

simplifies installation, improves portability, and supports DevGuard's

zero-dependency design.

