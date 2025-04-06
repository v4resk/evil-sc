import os
import sys
import zipfile
import uuid
import shutil
import tempfile
from colorama import Fore
import subprocess

def insert_custom_xml(docx_path, xml_path, output_path=None):
    """
    Insert a custom XML part into an Office document using the doctrack_bin utility.
    If the document doesn't exist, it will be created.
    
    Args:
        docx_path (str): Path to the Office document
        xml_path (str): Path to the XML file to insert
        output_path (str, optional): Path to save the modified document. If None, uses the input path.
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not os.path.exists(xml_path):
        print(f"{Fore.RED}[!] {Fore.WHITE}Error: XML file not found: {xml_path}")
        return False
    
    # If no output path is specified, use the input path
    if output_path is None:
        output_path = docx_path
    
    try:
        # Get the directory where the binary is located
        binary_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils")
        binary_path = os.path.join(binary_dir, "doctrack_bin")
        
        # Construct the command to run doctrack_bin
        # The -i parameter will create the file if it doesn't exist
        cmd = [binary_path, "--input", docx_path, "--output", output_path, "--custom-part", xml_path]
        
        # Run the command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if the command was successful
        if result.returncode == 0:
            print(f"{Fore.GREEN}[+] {Fore.WHITE}Successfully inserted custom XML part into {output_path}")
            return True
        else:
            print(f"{Fore.RED}[!] {Fore.WHITE}Error: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"{Fore.RED}[!] {Fore.WHITE}Error: {str(e)}")
        return False

def is_office_document(file_path):
    """
    Check if a file is a valid Office document
    
    Args:
        file_path (str): Path to the file
    
    Returns:
        bool: True if it's an Office document, False otherwise
    """
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # Check for common Office document files
            if '[Content_Types].xml' in zip_ref.namelist():
                return True
            return False
    except zipfile.BadZipFile:
        return False

def list_custom_xml(docx_path):
    """
    List all custom XML parts in an Office document using the doctrack_bin utility
    
    Args:
        docx_path (str): Path to the Office document
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not os.path.exists(docx_path):
        print(f"{Fore.RED}[!] {Fore.WHITE}Error: Office document not found: {docx_path}")
        return False
    
    try:
        # Get the directory where the binary is located
        binary_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils")
        binary_path = os.path.join(binary_dir, "doctrack_bin")
        
        # Construct the command to run doctrack_bin with inspect option
        cmd = [binary_path, "--input", docx_path, "--inspect"]
        
        # Run the command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if the command was successful
        if result.returncode == 0:
            # Print the output from doctrack_bin
            print(result.stdout)
            return True
        else:
            print(f"{Fore.RED}[!] {Fore.WHITE}Error: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"{Fore.RED}[!] {Fore.WHITE}Error: {str(e)}")
        return False

def extract_custom_xml(docx_path, output_dir=None):
    """
    Extract all custom XML parts from an Office document
    
    Args:
        docx_path (str): Path to the Office document
        output_dir (str, optional): Directory to save the extracted XML files. If None, uses current directory.
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not os.path.exists(docx_path):
        print(f"{Fore.RED}[!] {Fore.WHITE}Error: Office document not found: {docx_path}")
        return False
    
    # Check if the file is a valid Office document
    if not is_office_document(docx_path):
        print(f"{Fore.RED}[!] {Fore.WHITE}Error: Not a valid Office document: {docx_path}")
        return False
    
    # If no output directory is specified, use the current directory
    if output_dir is None:
        output_dir = os.getcwd()
    
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Extract the Office document
        with zipfile.ZipFile(docx_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Check if customXml directory exists
        custom_xml_dir = os.path.join(temp_dir, 'customXml')
        if not os.path.exists(custom_xml_dir):
            print(f"{Fore.YELLOW}[*] {Fore.WHITE}No custom XML parts found in {docx_path}")
            return True
        
        # Extract all XML files in the customXml directory
        xml_files = [f for f in os.listdir(custom_xml_dir) if f.endswith('.xml') and not f.endswith('Props.xml')]
        
        if not xml_files:
            print(f"{Fore.YELLOW}[*] {Fore.WHITE}No custom XML parts found in {docx_path}")
            return True
        
        print(f"{Fore.GREEN}[+] {Fore.WHITE}Extracting {len(xml_files)} custom XML part(s) from {docx_path}:")
        
        for i, xml_file in enumerate(xml_files, 1):
            xml_path = os.path.join(custom_xml_dir, xml_file)
            output_path = os.path.join(output_dir, f"extracted_{i}.xml")
            
            # Copy the XML file to the output directory
            shutil.copy2(xml_path, output_path)
            print(f"  {i}. Extracted to {output_path}")
        
        return True
    
    except Exception as e:
        print(f"{Fore.RED}[!] {Fore.WHITE}Error: {str(e)}")
        return False
    
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir) 