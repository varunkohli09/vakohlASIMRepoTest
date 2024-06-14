import requests
import yaml
import re
import os
import subprocess
from datetime import datetime
from urllib.parse import urlparse

#variables
#SentinelRepoUrl = f'https://raw.githubusercontent.com/Azure/Azure-Sentinel'
SentinelRepoUrl = 'https://raw.githubusercontent.com/vakohl/vakohlASIMRepoTest'
SampleDataPath = '/Sample%20Data/ASIM/'

# Global array to store results
results = []

# Global dictionary to store schema information
SchemaInfo = [
    {"SchemaName": "AuditEvent", "SchemaVersion": "0.1", "SchemaTitle":"ASIM Audit Event Schema", "SchemaLink": "https://aka.ms/ASimAuditEventDoc"},
    {"SchemaName": "Authentication", "SchemaVersion": "0.1.3","SchemaTitle":"ASIM Authentication Schema","SchemaLink": "https://aka.ms/ASimAuthenticationDoc"},
    # Add more schemas as needed
]

def run():
    # Get modified ASIM Parser files along with their status
    current_directory = os.getcwd()
    print(current_directory)
    GetModifiedFiles = "git diff --name-only origin/main -- C:\\Users\\vakohl\\Documents\\TestToBeDeleted\\varunkohli09\\vakohlASIMRepoTest\\Parsers"
    try:
        modified_files = subprocess.check_output(GetModifiedFiles, shell=True).decode()
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing the command: {e}")
    
    # Command to get the current commit number
    command = "git rev-parse HEAD"
    # Execute the command and store the result in a variable
    try:
        commit_number = subprocess.check_output(command, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing the command: {e}")

    # Construct ASim Sample Data URL
    ASIMSampleDataURL = f'{SentinelRepoUrl}/{commit_number}/{SampleDataPath}'

    # Split the output into lines
    modified_files_lines = modified_files.split("\n")
    Parser_yaml_files = [line for line in modified_files_lines if line.split('/')[-1].startswith('ASim') and line.endswith('.yaml')]
    for parser in Parser_yaml_files:
        # Use regular expression to extract SchemaName from the parser filename
        SchemaNameMatch = re.search(r'ASim(\w+)/', parser)
        if SchemaNameMatch:
            SchemaName = SchemaNameMatch.group(1)
        else:
            SchemaName = None
        # Check if changed file is a union parser
        if parser.endswith(f'ASim{SchemaName}.yaml'):
            continue
        # Construct the parser URL
        ASimParserUrl = f'{SentinelRepoUrl}/{commit_number}/{parser}'
        # Construct union parser URL
        ASimUnionParserURL = f'{SentinelRepoUrl}/{commit_number}/Parsers/ASim{SchemaName}/Parsers/ASim{SchemaName}.yaml'
        print("***********************************")
        print("Performing tests for ASim Parser")
        print("***********************************")

        ASimParser = read_github_yaml(ASimParserUrl)
        ASimUnionParser = read_github_yaml(ASimUnionParserURL)

        results = extract_and_check_properties(ASimParser, ASimUnionParser,"ASim", ASimParserUrl, ASIMSampleDataURL)
        for result in results:
            print(result)

        print("***********************************")
        print("Performing tests for vim Parser")
        print("***********************************")

        # Replace 'ASim' with 'vim' in the filename
        # Extract the filename from ASimParserUrl
        ASimParserfilename = ASimParserUrl.split('/')[-1]
        # Replace 'ASim' with 'vim' in the filename
        vimParserfilename = ASimParserfilename.replace('ASim', 'vim')
        vimParserUrl = ASimParserUrl.replace(ASimParserfilename, vimParserfilename)

        # Extract the filename from url2
        ASimUnionParserfilename = ASimUnionParserURL.split('/')[-1]
        # Replace 'ASim' with 'vim' in the filename
        imUnionParserfilename = ASimUnionParserfilename.replace('ASim', 'im')
        vimUnionParserUrl = ASimUnionParserURL.replace(ASimUnionParserfilename, imUnionParserfilename)

        vimParser = read_github_yaml(vimParserUrl)
        vimUnionParser = read_github_yaml(vimUnionParserUrl)

        # Check if vim parser properties
        results = extract_and_check_properties(vimParser, vimUnionParser,"vim", vimParserUrl, ASIMSampleDataURL)
        for result in results:
            print(result)

def read_github_yaml(url):
    response = requests.get(url)
    if response.status_code == 200:
        yaml_file = yaml.safe_load(response.text)
        return yaml_file
    else:
        return None

def extract_and_check_properties(Parser_file, Union_Parser__file, FileType, ParserUrl, ASIMSampleDataURL):
    """
    Extracts properties from the given YAML files and checks if they exist in another YAML file.

    Args:
        yaml_file (dict): The YAML file to extract properties from.
        another_yaml_file (dict): The YAML file to check for the existence of properties.

    Returns:
        list: A list of tuples containing the property name, the property type, and a boolean indicating if the property exists in another_yaml_file.
    """
    results = []
    parser_name = Parser_file.get('ParserName')
    equivalent_built_in_parser = Parser_file.get('EquivalentBuiltInParser')
    parser = Parser_file.get('Parser', {})
    title = parser.get('Title')
    version = parser.get('Version')
    last_updated = parser.get('LastUpdated')
    normalization = Parser_file.get('Normalization', {})
    schema = normalization.get('Schema')
    schemaVersion = normalization.get('Version')
    references = Parser_file.get('References', [])

    # ParserQuery property is the KQL query extracted from the YAML file
    parser_query = Parser_file.get('ParserQuery', '')

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
        if parser_name in Union_Parser__file.get('ParserQuery', ''):
            results.append((parser_name, 'ParserName exist in union parser', True))
        else:
            results.append((parser_name, 'ParserName not found in union parser', False))

    # Check if equivalent_built_in_parser exists in another_yaml_file's 'Parsers'
    if equivalent_built_in_parser:
        if equivalent_built_in_parser in Union_Parser__file.get('Parsers', []):
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
    parsed_url = urlparse(ParserUrl)
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
    return results

# Script starts here
run()