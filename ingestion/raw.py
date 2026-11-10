import gzip
import os
from pathlib import Path   # <- corrigé
"""
Read from data all files
in:data [directory]
out:list of rows
"""
def to_rows(path:list):
    data_dir=Path(path)
    try:
        files = os.listdir(path)
    except Exception as e:
        print(path + ' error')
        return                      # <- ajouté
    rows = []                       # <- ajouté
    try:
      
        for file in files:
            file_path=path+'/'+file
            open_type=gzip.open(file_path,mode='rt') if file.endswith('.gz') else open(file_path)  # <- indentation + file_path
            with open_type as f:
                rows.extend(f.readlines())   # <- au lieu de return

        return rows                 # <- ajouté

    except FileNotFoundError  as e:
        print(e)
        return
    
if __name__ == "__main__":
    data=to_rows('./data')
    if data:
        print(data[:10])