
## Dataset Processing

| Command      | Description                                      |
|--------------|--------------------------------------------------|
| search       | Search for events in Splunk                      |
| where        | Filter results using a Boolean expression        |
| fields       | Include or exclude fields                        |
| table        | Display results as a table                       |
| sort         | Sort results                                     |
| dedup        | Remove duplicate events                          |
| rename       | Rename fields                                    |
| eval         | Calculate and create new fields                  |
| rex          | Extract fields using regular expressions         |
| replace      | Replace values in fields                         |
| fillnull     | Replace null values                              |
| makemv       | Create multivalue fields                         |
| mvexpand     | Expand multivalue fields into separate events    |
| transaction  | Group events into transactions                   |
| eventstats   | Add summary statistics to events                 |
| streamstats  | Calculate statistics for each event              |
| stats        | Calculate aggregate statistics                   |
| tstats       | Accelerated statistics (faster, uses data models)|
| chart        | Create charts (pivot tables)                     |
| timechart    | Create time-based charts                         |
| top          | Display most common values                       |
| rare         | Display least common values                      |
| head         | Return the first N results                       |
| tail         | Return the last N results                        |
| reverse      | Reverse the order of results                     |
| join         | Join results from two searches                   |
| append       | Append results from another search               |
| appendcols   | Append columns from another search               |
| appendpipe   | Run a subsearch and append results               |
| lookup       | Enrich data using lookup tables                  |
| inputlookup  | Read data from a lookup table                    |
| outputlookup | Write results to a lookup table                  |
| lookup       | Enrich events with external data                 |
| map          | Run a search for each result                     |
| subsearch    | Run a search within another search               |
| eval         | Calculate new fields or values                   |

## Data Manipulation

| Command      | Description                                      |
|--------------|--------------------------------------------------|
| bin          | Bucket data into ranges                          |
| bucket       | Alias for bin                                    |
| convert      | Convert field values (e.g., time formats)        |
| extract      | Extract fields from raw data                     |
| kv           | Extract key-value pairs                          |
| multikv      | Extract fields from multi-line events            |
| spath        | Extract fields from JSON or XML                  |
| xmlkv        | Extract fields from XML                          |

## Reporting & Visualization

| Command      | Description                                      |
|--------------|--------------------------------------------------|
| stats        | Aggregate statistics (sum, avg, count, etc.)     |
| chart        | Pivot table                                      |
| timechart    | Time-based chart                                 |
| top          | Most frequent values                             |
| rare         | Least frequent values                            |
| gauge        | Display gauge visualizations                     |
| xyseries     | Create XY series for charting                    |

## Miscellaneous

| Command      | Description                                      |
|--------------|--------------------------------------------------|
| metadata     | Return metadata about indexes                    |
| typeahead    | Provide search suggestions                       |
| rest         | Access REST endpoints                            |
| sistats      | Summary indexing statistics                      |
| loadjob      | Load results from a saved search                 |
| delete       | Mark events as deleted (admin only)              |
| sendalert    | Trigger a custom alert action                    |

---

## Useful Links

- [Splunk Search Reference (Official)](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchCommands)
- [Splunk Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/WelcometotheSearchTutorial)

