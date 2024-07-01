# This class should create the .cpp file

from core.config.config import Config
from core.controlers.EncryptorsChain import EncryptorsChain
import shutil
import os

class TemplateLoader:
    def __init__(self,_vars):
        self.template_file = Config().get('FILES', 'template_file')
        for key, value in _vars.items():
            setattr(self, key, value)

        #Copy template file to build emplacement
        self.copy_new_template_file()
        #Load encryptors chain
        self.load_encryptors_chain()

    def test(self):
        print(vars(self))

    def copy_new_template_file(self):
        src_file = f"{Config().get('FOLDERS', 'methods')}/{self.method}.cpp"
        dest_file = self.template_file
        try:
            if not os.path.isfile(src_file):
                raise FileNotFoundError(f"The source file {src_file} does not exist.")

            dest_folder = os.path.dirname(dest_file)
            if not os.path.isdir(dest_folder):
                os.makedirs(dest_folder)
            
            # Copy the source file to the destination
            shutil.copy2(src_file, dest_file)
            #print(f"File {src_file} copied to {dest_file}.")
        
        except Exception as e:
            print(f"Error: {e}")
    
    def load_encryptors_chain(self):
        self.encryptors_chain = EncryptorsChain()
        pass