import requests
import yaml
import re
from datetime import datetime
from urllib.parse import urlparse
import subprocess

# Provide ASim parser filename
#_ASimParserFileName = "ASimAuthenticationGithub"
_ASimParserFileName = "ASimAuditEventGithubWebhook"
#_ASimParserFileName = "ASimAuthenticationAuth0"
_SchemaName = "AuditEvent"
#_SchemaName = "Authentication"

# Provide Commit number
_CommitNumber = "20ad70075116ece323f4243e4c8a2299df486d18"

# Global array to store results
results = []

# Global dictionary to store schema information
SchemaInfo = [
    {"SchemaName": "AuditEvent", "SchemaVersion": "0.1", "SchemaTitle":"ASIM Audit Event Schema", "SchemaLink": "https://aka.ms/ASimAuditEventDoc"},
    {"SchemaName": "Authentication", "SchemaVersion": "0.1.3","SchemaTitle":"ASIM Authentication Schema","SchemaLink": "https://aka.ms/ASimAuthenticationDoc"},
    # Add more schemas as needed
]

url1 = f'https://raw.githubusercontent.com/Azure/Azure-Sentinel/{_CommitNumber}/Parsers/ASim{_SchemaName}/Parsers/{_ASimParserFileName}.yaml'
url2 = f'https://raw.githubusercontent.com/Azure/Azure-Sentinel/{_CommitNumber}/Parsers/ASim{_SchemaName}/Parsers/ASim{_SchemaName}.yaml'
ASIMSampleDataURL = f'https://raw.githubusercontent.com/Azure/Azure-Sentinel/{_CommitNumber}/Sample%20Data/ASIM/'

def run():
    # Get modified ASIM Parser files along with their status
    command = "git diff --name-status origin/main -- ./../../../Parsers/"
    modified_files_status = subprocess.check_output(command, shell=True).decode()
    # Split the output into lines
    modified_files_status_lines = modified_files_status.split("\n")
    for line in modified_files_status_lines:
        print("***********************************")
        print("Performing tests for ASim Parser")
        print("***********************************")
        extract_and_check_properties(yaml_file1, yaml_file2,"ASim")
        for result in results:
            print(result)

        print("***********************************")
        print("Performing tests for vim Parser")
        print("***********************************")

        # Replace 'ASim' with 'vim' in the filename
        # Extract the filename from url1
        filename = url1.split('/')[-1]
        # Replace 'ASim' with 'vim' in the filename
        new_filename = filename.replace('ASim', 'vim')
        new_url1 = url1.replace(filename, new_filename)

        # Extract the filename from url2
        filename = url2.split('/')[-1]
        # Replace 'ASim' with 'vim' in the filename
        new_filename = filename.replace('ASim', 'im')
        new_url2 = url2.replace(filename, new_filename)

        yaml_file1 = read_github_yaml(new_url1)
        yaml_file2 = read_github_yaml(new_url2)

        # Check if vim parser properties
        results = []
        extract_and_check_properties(yaml_file1, yaml_file2,"vim")
        for result in results:
            print(result)

    

def read_github_yaml(url):
    response = requests.get(url)
    if response.status_code == 200:
        yaml_file = yaml.safe_load(response.text)
        return yaml_file
    else:
        return None

def extract_and_check_properties(yaml_file, another_yaml_file, FileType):
    """
    Extracts properties from the given YAML files and checks if they exist in another YAML file.

    Args:
        yaml_file (dict): The YAML file to extract properties from.
        another_yaml_file (dict): The YAML file to check for the existence of properties.

    Returns:
        list: A list of tuples containing the property name, the property type, and a boolean indicating if the property exists in another_yaml_file.
    """
    parser_name = yaml_file.get('ParserName')
    equivalent_built_in_parser = yaml_file.get('EquivalentBuiltInParser')
    parser = yaml_file.get('Parser', {})
    title = parser.get('Title')
    version = parser.get('Version')
    last_updated = parser.get('LastUpdated')
    normalization = yaml_file.get('Normalization', {})
    schema = normalization.get('Schema')
    schemaVersion = normalization.get('Version')
    references = yaml_file.get('References', [])

    # ParserQuery property is the KQL query extracted from the YAML file
    parser_query = yaml_file.get('ParserQuery', '')

    # Use a regular expression to find 'EventProduct' in the KQL query
    match = re.search(r'EventProduct\s*=\s*[\'"](\w+)[\'"]', parser_query)

    # If 'EventProduct' was found in the KQL query, extract its value
    if match:
        event_product = match.group(1)
        results.append((event_product, 'EventProduct found in parser query', True))
    # If 'EventProduct' was not found in the KQL query, add to results
    else:
        results.append(('EventProduct', 'EventProduct not found in Parser query', False))

    # Use a regular expression to find 'EventVendor' in the KQL query
    match = re.search(r'EventVendor\s*=\s*[\'"](\w+)[\'"]', parser_query)

    # If 'EventVendor' was found in the KQL query, extract its value
    if match:
        event_vendor = match.group(1)
        results.append((event_vendor, 'EventVendor found in parser query', True))
    # If 'EventVendor' was not found in the KQL query, add to results
    else:
        results.append(('EventVendor', 'EventVendor not found in Parser query', False))

    # Check if parser_name exists in another_yaml_file's 'ParserQuery'
    if parser_name:
        if parser_name in another_yaml_file.get('ParserQuery', ''):
            results.append((parser_name, 'ParserName exist in union parser', True))
        else:
            results.append((parser_name, 'ParserName not found in union parser', False))

    # Check if equivalent_built_in_parser exists in another_yaml_file's 'Parsers'
    if equivalent_built_in_parser:
        if equivalent_built_in_parser in another_yaml_file.get('Parsers', []):
            results.append((equivalent_built_in_parser, 'EquivalentBuiltInParser exist in union parser', True))
        else:
            results.append((equivalent_built_in_parser, 'EquivalentBuiltInParser not found in union parser', False))

    # Check if title exists in yaml_file's 'Parser'->'Title'       
    if title:
        results.append((title, 'This value exist in Title property', True))
    else:
        results.append(('Title', 'Title not found in parser YAML', False))
    # Check if version exists in yaml_file's 'Parser'->'Version' and matches the format X.X.X
    if version:
        if re.match(r'^\d+\.\d+\.\d+$', version):
            results.append((version, 'This value exist in Version property', True))
        else:
            results.append((version, 'Version exist but format is incorrect', False))
    else:
        results.append(('Version', 'Version not found in parser YAML', False))

    # Check if last_updated exists in yaml_file's 'Parser'->'LastUpdated' and matches the format MMM DD YY
    if last_updated:
        try:
            datetime.strptime(last_updated, '%b %d, %Y')
            results.append((last_updated, 'This value exist in LastUpdated property', True))
        except ValueError:
            results.append((last_updated, 'LastUpdated exist but format is incorrect', False))
    else:
        results.append(('LastUpdated', 'LastUpdated not found in parser YAML', False))
    
    # Check if schema exists in yaml_file's 'Normalization'->'Schema' and matches with our SchemaInfo
    if schema:
        for info in SchemaInfo:
            if info['SchemaName'] == schema:
                results.append((schema, 'Schema name is correct', True))
                break
        else:
            results.append((schema, 'Schema name is incorrect', False))
    else:
        results.append(('Schema', 'Schema name not found in parser YAML', False))
    
    # Check if Schema Version exists in yaml_file's 'Normalization'->'Schema' and matches with our SchemaInfo
    if schemaVersion:
        for info in SchemaInfo:
            if schema == info.get('SchemaName'):
                if info['SchemaVersion'] == schemaVersion and info['SchemaName'] == schema:
                    results.append((schemaVersion, 'Schema Version is correct', True))
                    break
                else:
                    results.append((schemaVersion, 'Schema Version is incorrect', False))
    else:
        results.append(('Version', 'Schema Version not found in parser YAML', False))

    # Check if references exist in yaml_file's 'References'
    if references:
        for ref in references:
            title = ref.get('Title')
            link = ref.get('Link')

            for info in SchemaInfo:
                titleSchemaInfo = info.get('SchemaTitle')
                linkSchemaInfo = info.get('SchemaLink')
                if schema == info.get('SchemaName'):
                    if title == titleSchemaInfo and link == linkSchemaInfo:
                        results.append((title, 'Schema specific reference link matching', True))
                    elif title == 'ASIM' and link == 'https:/aka.ms/AboutASIM':
                        results.append((title, 'ASim doc reference link matching', True))
                    else:
                        results.append((title, 'reference title or link not matching', False))
    else:
        results.append(('References', 'References', False))

    # Check if ParserName exists in yaml_file and matches the format ASIMAuditEvent<ProductName>
    if parser_name:
        if re.match(rf'{FileType}{schema}', parser_name):
            results.append((parser_name, 'ParserName is in correct format', True))
        else:
            results.append((parser_name, 'ParserName is not in correct format', False))
    else:
        results.append(('ParserName', 'ParserName not found', False))

    # Check if EquivalentBuiltInParser exists in yaml_file and matches the format _ASIM_<Schema><ProductName>
    FileType = "Im" if FileType == "vim" else FileType
    if equivalent_built_in_parser:
        if re.match(rf'_{FileType}_{schema}_', equivalent_built_in_parser):
            results.append((equivalent_built_in_parser, 'EquivalentBuiltInParser is in correct format', True))
        else:
            results.append((equivalent_built_in_parser, 'EquivalentBuiltInParser is not in correct format', False))
    else:
        results.append(('EquivalentBuiltInParser', 'EquivalentBuiltInParser not found', False))

    # Check if tester files exists or not
    
    # Construct ASim DataTest.csv filename
    DataTestFileName = f'{event_vendor}_{event_product}_{FileType}{schema}_DataTest.csv'
    # Construct ASim SchemaTest.csv filename
    SchemaTestFileName = f'{event_vendor}_{event_product}_{FileType}{schema}_SchemaTest.csv'
    Testerfilenames = [DataTestFileName, SchemaTestFileName]
    # Parse the URL
    parsed_url = urlparse(url1)
    # Extract everything except the filename
    url_without_filename = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path.rsplit('/', 2)[0]
    for filename in Testerfilenames:
        # DataTest.csv full URL construct
        DataTestUrl = url_without_filename + "//Tests//" + filename
        response = requests.get(DataTestUrl)
        if response.status_code == 200:
            results.append((filename, 'Tester file exists', True))
        else:
            results.append((filename, 'Tester file does not exist', False))
    
    # Check if sample data files exists or not (Only applicable for ASim FileType)
    
    if FileType == "ASim":
        # construct filename
        SampleDataFile = f'{event_vendor}_{event_product}_{FileType}{schema}_IngestedLogs.csv'
        SampleDataUrl = ASIMSampleDataURL+SampleDataFile
        # check if file exists
        response = requests.get(SampleDataUrl)
        if response.status_code == 200:
            results.append((SampleDataFile, 'Sample data exists', True))
        else:
            results.append((SampleDataFile, 'Sample data does not exist', False))

# yaml_file1 = read_github_yaml(url1)
# yaml_file2 = read_github_yaml(url2)
print("***********************************")
print("Performing tests for ASim Parser")
print("***********************************")
extract_and_check_properties(yaml_file1, yaml_file2,"ASim")
for result in results:
    print(result)

print("***********************************")
print("Performing tests for vim Parser")
print("***********************************")

# Replace 'ASim' with 'vim' in the filename
# Extract the filename from url1
filename = url1.split('/')[-1]
# Replace 'ASim' with 'vim' in the filename
new_filename = filename.replace('ASim', 'vim')
new_url1 = url1.replace(filename, new_filename)

# Extract the filename from url2
filename = url2.split('/')[-1]
# Replace 'ASim' with 'vim' in the filename
new_filename = filename.replace('ASim', 'im')
new_url2 = url2.replace(filename, new_filename)

yaml_file1 = read_github_yaml(new_url1)
yaml_file2 = read_github_yaml(new_url2)

# Check if vim parser properties
results = []
extract_and_check_properties(yaml_file1, yaml_file2,"vim")
for result in results:
    print(result)